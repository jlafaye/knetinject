/* knetinject.c - A netif_rx packet injection module
 *
 * Copyright (C) 2012 by Julien Lafaye
 *
 */

//#define MODULE
//#define LINUX
//#define __KERNEL__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <asm/uaccess.h> /* copy from/to user */
#include "kni.h"

// ------------------------------------------------------

/* Module loading/unloading operations */
int kni_init(void);
void kni_exit(void);

/* Network access operations */
struct kni_net_packet {
    struct kni_net_packet *next;
    struct net_device *dev;
    int datalen;
    u8 data[ETH_DATA_LEN];
};

struct net_device *kni_net;
struct kni_net_priv {
    struct net_device_stats   stats;
    int    status;
    struct kni_net_packet *ppool;
    struct kni_net_packet *pqueue;
    int    int_enabled;
    spinlock_t lock;
    struct net_device        *dev;
    struct napi_struct        napi;
    wait_queue_head_t         wait_queue;
};

/* Buffer management */
void kni_net_release_buffer(struct kni_net_packet *pkt);
void kni_net_enqueue_buffer(struct net_device *dev, struct kni_net_packet *pkt);
struct kni_net_packet *kni_net_dequeue_buffer(struct net_device *dev);
struct kni_net_packet *kni_net_get_buffer(struct net_device *dev);

/* Pool management */
int pool_size = 64;
void kni_net_setup_pool(struct net_device *dev);
void kni_net_release_pool(struct net_device *dev);

/* Device management */
static void kni_net_ints(struct net_device *dev, int enable);

/* Interrupt management */
static void kni_net_tx_timeout(struct net_device *dev);
static void (*kni_net_interrupt)(int, void*, struct pt_regs *);
static void kni_net_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

/* Netdevice operations */
void kni_net_init(struct net_device *dev);
int  kni_net_open(struct net_device *dev);
int  kni_net_release(struct net_device *dev);
int  kni_net_config(struct net_device *dev, struct ifmap *map);
netdev_tx_t kni_net_tx(struct sk_buff *skb, struct net_device *dev);
int  kni_net_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
struct net_device_stats* kni_net_stats(struct net_device *dev);
int  kni_net_change_mtu(struct net_device *dev, int new_mtu);
// void kni_net_tx_timeout(struct net_device *dev);

static const struct net_device_ops kni_net_ops = {
    .ndo_open       = kni_net_open,
    .ndo_stop       = kni_net_release,
    .ndo_set_config = kni_net_config,
    .ndo_start_xmit = kni_net_tx,
    .ndo_do_ioctl   = kni_net_ioctl,
    .ndo_get_stats  = kni_net_stats,
    .ndo_change_mtu = kni_net_change_mtu,
    .ndo_tx_timeout = kni_net_tx_timeout
};

/* NAPI operations */
static int kni_net_poll(struct napi_struct *napi, int budget);

void kni_net_rx(struct net_device *dev, struct kni_net_packet *pkt);

/* File access operations */
int kni_open   (struct inode *inode, struct file *filp);
int kni_release(struct inode *inode, struct file *filp);
ssize_t kni_read (struct file *filp, char *buf, size_t count, loff_t *f_pos);
ssize_t kni_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

struct file_operations kni_fops = {
    read:    kni_read,
    write:   kni_write,
    open:    kni_open,
    release: kni_release
};

/* Global variables */
unsigned int kni_major = 0;
unsigned int kni_minor = 0;

char* kni_buffer;

// ------------------------------------------------------

void kni_net_init(struct net_device *dev)
{
    struct kni_net_priv *priv;

    ether_setup(dev);   /* assign some of the fields */
    
    dev->netdev_ops = &kni_net_ops;
        
    /* keep the default flags, just add NOARP */
    dev->flags          |= IFF_NOARP;
    dev->features       |= NETIF_F_NO_CSUM;
   
	/*
	 * Then, initialize the priv field. This encloses the statistics
	 * and a few private fields.
	 */
    priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct kni_net_priv)); 

    priv->dev = dev;
    netif_napi_add(dev, &priv->napi, kni_net_poll, 2);
	/* The last parameter above is the NAPI "weight". */
    spin_lock_init(&priv->lock);
    init_waitqueue_head(&priv->wait_queue);

    kni_net_ints(dev, 1); /* enable interrupts */
    kni_net_setup_pool(dev);
}

static void kni_net_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    int statusword;
    struct kni_net_priv *priv;
    
	/*
	 * As usual, check the "device" pointer for shared handlers.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

    PDEBUG("kni_net_napi_interrupt(irq=%d,dev_id=%p,regs=%p)\n",
           irq, dev_id, regs);

	/* paranoid */
	if (!dev)
		return;
    
    /* Lock the device */
    priv = netdev_priv(dev);
    spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
    PDEBUG("kni_net_napi_interrupt: ... statusword: 0x%04x\n", statusword);
	if (statusword & KNI_NET_INTR) {
		kni_net_ints(dev, 0);  /* Disable further interrupts */
        PDEBUG("kni_net_napi_interrupt: ... napi_schedule\n");
        napi_schedule(&priv->napi);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	return;
}

static void kni_net_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    int statusword;
    struct kni_net_priv *priv;
    struct kni_net_packet *pkt = NULL;

	/*
	 * As usual, check the "device" pointer to be sure it is
	 * really interrupting.
	 * Then assign "struct device *dev"
	 */
	struct net_device *dev = (struct net_device *)dev_id;
	/* ... and check with hw if it's really ours */

	/* paranoid */
	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & KNI_NET_INTR) {
		/* send it to kni_net_rx for handling */
		pkt = priv->pqueue;
		if (pkt) {
			priv->pqueue = pkt->next;
			kni_net_rx(dev, pkt);
		}
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt) kni_net_release_buffer(pkt); /* Do this outside the lock! */
	return;
}

int kni_net_open(struct net_device *dev)
{
	/* 
	 * Assign the hardware address of the board: use "\0KNPL0".
     * The first byte is '\0' to avoid being a multicast
	 * address (the first byte of multicast addrs is odd).
	 */
    memcpy(dev->dev_addr, "\0KNPLO", ETH_ALEN);
    netif_start_queue(dev);
    return 0;
}

int kni_net_release(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
int kni_net_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "knetinject: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
        	/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}

/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
void kni_net_rx(struct net_device *dev, struct kni_net_packet *pkt)
{
    struct sk_buff *skb;
    struct kni_net_priv *priv = netdev_priv(dev);

	/*
	 * The packet has been retrieved from the transmission
	 * medium. Build an skb around it, so upper layers can handle it
	 */
	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */  
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);
  out:
	return;
}

/*
 * Transmit a packet (called by the kernel)
 */
int kni_net_tx(struct sk_buff *skb, struct net_device *dev)
{
    PDEBUG("kni_net_tx(skb=%p)\n", skb);
    return 0;
}

/*
 * Deal with a transmit timeout.
 */
void kni_net_tx_timeout(struct net_device *dev)
{
    PDEBUG("kni_net_tx_timeout\n");
    return;
}

/*
 * Ioctl commands 
 */
int kni_net_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	PDEBUG("ioctl\n");
	return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *kni_net_stats(struct net_device *dev)
{
	struct kni_net_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
int kni_net_change_mtu(struct net_device *dev, int new_mtu)
{
	// unsigned long flags;
	// struct snull_priv *priv = netdev_priv(dev);
	// spinlock_t *lock = &priv->lock;
    
	/* check ranges */
	// if ((new_mtu < 68) || (new_mtu > 1500))
		// return -EINVAL;
	/*
	 * Do anything you need, and the accept the value
	 */
	// spin_lock_irqsave(lock, flags);
	// dev->mtu = new_mtu;
	// spin_unlock_irqrestore(lock, flags);
	// return 0; /* success */
    return 0; /* success */
}

// ------------------------------------------------------
/*
 * Buffer/pool management.
 */
void kni_net_release_buffer(struct kni_net_packet *pkt)
{
    unsigned long flags;
    struct kni_net_priv *priv = netdev_priv(pkt->dev);

    spin_lock_irqsave(&priv->lock, flags);
    pkt->next   = priv->ppool;
    priv->ppool = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);

    /* Notify that we have a buffer available */
    wake_up(&priv->wait_queue);
    // if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
    // netif_wake_queue(pkt->dev); 
}

void kni_net_enqueue_buffer(struct net_device *dev, struct kni_net_packet *pkt)
{
    unsigned long flags;
    struct kni_net_priv *priv = netdev_priv(pkt->dev);

    spin_lock_irqsave(&priv->lock, flags);
    pkt->next    = priv->pqueue; /* FIXME - misorders packets */
    priv->pqueue = pkt;
    spin_unlock_irqrestore(&priv->lock, flags);
}

struct kni_net_packet *kni_net_dequeue_buffer(struct net_device *dev)
{
    // TODO: find where this method is used
    struct kni_net_priv *priv = netdev_priv(dev);
    struct kni_net_packet *pkt;
    unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->pqueue;
	if (pkt != NULL)
		priv->pqueue = pkt->next;
	spin_unlock_irqrestore(&priv->lock, flags);
    return pkt;
}

struct kni_net_packet *kni_net_get_buffer(struct net_device *dev)
{
    struct kni_net_priv *priv = netdev_priv(dev);
    unsigned long flags;
    struct kni_net_packet *pkt = NULL;
   
    spin_lock_irqsave(&priv->lock, flags);
    if (priv->ppool) { 
        pkt = priv->ppool; 
        priv->ppool = pkt->next;
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

static void kni_net_emit(const char *userbuf, int len, struct net_device *dev)
{
    /*
     * This functions creates a packet and 
     * enqueues it into the receive queue
     */
    int    ret;
    struct kni_net_packet *pkt;
    struct kni_net_priv   *priv;

    // PDEBUG("kni_net_emit(buf=%p,len=%d,dev=%p)\n",
    // userbuf, len, dev);

    priv = netdev_priv(dev);
    pkt  = kni_net_get_buffer(dev);

    /* TODO: have this reviewed by A. Berlemont */
    while (pkt == NULL) {
        ret  = wait_event_interruptible(priv->wait_queue, priv->ppool != NULL); 
        if (ret != 0) {
            return;
        }
    }

    ret  = copy_from_user(pkt->data, userbuf, len);

    if (ret != 0) {
        // TODO: improve error reporting
        pkt->datalen = 0;
    } else {
        pkt->datalen = len;
    }

    /* debug */
    if (0) {
        int i;
        PDEBUG("len is %i\n" KERN_DEBUG "data:", len);
        for (i=0; i<pkt->datalen; ++i) 
            printk(" %02x", pkt->data[i]&0xff);
        printk("\n");
    }

    /* 
     * Ok, now the packet is ready to be received
     */
    // priv = netdev_priv(dev);
    // pkt  = kni_net_get_buffer(dev);
    // memcpy(pkt->data, buf, len);
    // pkt->datalen = len;

    kni_net_enqueue_buffer(dev, pkt);
    PDEBUG("kni_net_emit ... int_enabled:%d\n",
           priv->int_enabled);
    if (priv->int_enabled) {
        priv->status |= KNI_NET_INTR;
        PDEBUG("kni_net_emit ... status: 0x%04x\n", priv->status);
        kni_net_interrupt(0, dev, NULL);
    }
}

// ------------------------------------------------------

/*
 * The poll implementation.
 */
static int kni_net_poll(struct napi_struct *napi, int budget)
{
    int npackets = 0;
	struct sk_buff *skb;
    struct kni_net_priv *priv = container_of(napi, struct kni_net_priv, napi);
    struct net_device      *dev  = priv->dev;
    struct kni_net_packet *pkt;

    PDEBUG("kni_net_poll(napi=%p, budget=%d)\n",
           napi, budget);
    
    while (npackets < budget && priv->pqueue) {
        pkt = kni_net_dequeue_buffer(dev);
        skb = dev_alloc_skb(pkt->datalen + 2);
        if (!skb) {
            if (printk_ratelimit())
                printk(KERN_NOTICE "knetreplay: packet dropped\n");
            priv->stats.rx_dropped++;
            kni_net_release_buffer(pkt);
            continue; 
        }
        skb_reserve(skb, 2); /* align IP on 16B boundary */
        memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);
        skb->dev       = dev; 
        skb->protocol  = eth_type_trans(skb, dev);
        skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
        netif_receive_skb(skb);
        
        /* Maintain stats */
        npackets++;
        priv->stats.rx_packets++;
        priv->stats.rx_bytes += pkt->datalen;
        kni_net_release_buffer(pkt);
    }

	/* If we processed all packets, we're done; tell the kernel and reenable ints */
	if (npackets < budget) {
		napi_complete(napi);
		kni_net_ints(dev, 1);
	}

    return npackets;
}

// ------------------------------------------------------

/*
 * Device pool management
 */
void kni_net_setup_pool(struct net_device *dev)
{
    struct kni_net_priv *priv = netdev_priv(dev);
    int i;
    struct kni_net_packet *pkt;

    priv->ppool = NULL;
    for (i=0; i<pool_size; ++i) {
        pkt = kmalloc(sizeof(struct kni_net_packet), GFP_KERNEL);
        if (pkt == NULL) {
            printk(KERN_NOTICE "Ran out of memory allocating packet pool\n");
            return;
        }
        pkt->dev    = dev;
        pkt->next   = priv->ppool;
        priv->ppool = pkt;
    }
}

void kni_net_release_pool(struct net_device *dev)
{
    struct kni_net_priv   *priv = netdev_priv(dev);
    struct kni_net_packet *pkt;

    while ((pkt = priv->ppool)) {
        priv->ppool = pkt->next;
        kfree(pkt);
        /* FIXME - in-flight packets ? */
    }
}

// ------------------------------------------------------

static void kni_net_ints(struct net_device *dev, int enable)
{
    struct kni_net_priv   *priv = netdev_priv(dev);
    PDEBUG("kni_net_ints(dev=%p,enable=%d)\n",
           dev, enable);
    priv->int_enabled = enable; 
}

// ------------------------------------------------------

int kni_open(struct inode *inode, struct file *filp)
{
    /* Success */
    return 0;
}

int kni_release(struct inode *inode, struct file *filp)
{
    return 0;
}

ssize_t kni_read(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
    return -EPERM;
}

ssize_t kni_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    int ret;
    struct kni_net_packet *pkt;
    struct kni_net_priv   *priv;

    // check size
    if (count > ETH_DATA_LEN) {
        return -ENOSPC;
    }

    // PDEBUG("kni_write(file=%p,buf=%p,count=%d,f_pos=%ld)\n",
    //       filp, buf, count, (long)*f_pos);

    /* Get a frame in our receive pool */
    priv = netdev_priv(kni_net);
    pkt  = kni_net_get_buffer(kni_net);
    
    /* TODO: have this reviewed by A. Berlemont */
    /* Wait until one is available */
    while (pkt == NULL) {
        ret  = wait_event_interruptible(priv->wait_queue, priv->ppool != NULL); 
        if (ret != 0) {
            return -ERESTARTSYS;
        }
    }

    /* Copy user data to our prepared frame */
    ret = copy_from_user(pkt->data, buf, count);

    if (ret != 0) {
        pkt->datalen = 0;
        ret          = -EBUSY;
    } else {
        pkt->datalen = count;
        ret          = count;
        *f_pos      += count;
    }

    /* If an error has occurred, a packet with length = 0 will be received */
    kni_net_enqueue_buffer(kni_net, pkt);

    if (priv->int_enabled) {
        priv->status |= KNI_NET_INTR;
        PDEBUG("kni_net_emit ... status: 0x%04x\n", priv->status);
        kni_net_interrupt(0, kni_net, NULL);
    }

    return ret;
}


// ------------------------------------------------------

int kni_init(void)
{
    int res;
    
    /* Select interrupt handling method */
    kni_net_interrupt = kni_net_regular_interrupt;

    /* Registering device */
    res = register_chrdev(kni_major, "kni", &kni_fops);

    if (kni_major < 0) {
        printk(KERN_ALERT "knetinject: cannot obtain major number %d\n", kni_major);
        return res;
    } else {
        kni_major = res;
    }

    /* Allocating memory for the buffer */
    kni_buffer = kmalloc(1, GFP_KERNEL);
    if (!kni_buffer) {
        res = -ENOMEM;
        goto fail;
    }
    memset(kni_buffer, 0, 1);

    /* Allocating netdevice */
    kni_net = alloc_netdev(sizeof(struct kni_net_priv), "kni%d", kni_net_init);
    if (!kni_net)
        goto fail;

    res = register_netdev(kni_net);
    if (res) {
        printk("knetinject: error %i registering device '%s'\n", 
               res, kni_net->name);
        goto fail;
    }

    printk(KERN_INFO "knetinject: loaded\n");
    return 0;

  fail:
    kni_exit();
    return res;
}

void kni_exit(void)
{
    /* Cleaning network device */
    if (kni_net) {
        unregister_netdev(kni_net);
        kni_net_release_pool(kni_net);
        free_netdev(kni_net);
    }

    /* Freeing buffer memory */
    if (kni_buffer)
        kfree(kni_buffer);

    /* Freeing the major number */
    unregister_chrdev(kni_major, "kni");

    printk(KERN_INFO "knetinject: unloaded\n");
}

// ------------------------------------------------------

MODULE_LICENSE("GPL");
module_init(kni_init);
module_exit(kni_exit);
