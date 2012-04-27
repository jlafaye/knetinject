/* kni.h
 *
 * Copyright (C) 2012 by Julien Lafaye
 *
 */

#undef PDEBUG
#define PDEBUG(fmt, args...) printk(KERN_DEBUG "knetinject:" fmt, ##args)

#define KNI_NET_INTR 0x0001
