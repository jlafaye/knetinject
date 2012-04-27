knetinject: A virtual network driver to inject arbitrary packets into the network stack
---------------------------------------------------------------------------------------

When properly loaded & configured, the knetinject driver features:
- a *virtual network device* kni0 which can be configured & accessed as any 'regular' driver
- a *character device*, /dev/kni0 

A userspace application can write to /dev/kni0. Every time a *write* is issued to the character device, a packet will be *injected* to the network stack through the kni0 device.

knetinject was created to be able to *replay multicast trafic* without having to rely on two servers (generation + reception). Once generated a network trafic capture (e.g. through) tcpdump, this capture can be fed into the application by writing it to the character device.

Compilation of kernel module
----------------------------

```
cd kernel
make
```

Kernel headers are required for the compilation to succeed. The Makefile should automatically detect the location of those headers. If this is not the case, you can select by overriding the KERNEL_DIR variable using by the compilation script

```
make KERNEL_DIR=/lib/modules/3.0.0-1-686-pae/build modules
```
-
Loading the kernel module

```
cd scripts
./kni_load.sh
```

This will:
* create a network interface kni0
* create a device file /dev/kni

Sample usage
------------

The misc directory contains dumps of UDP backed multicast trafic addressed to group 226.0.0.1. 

The tools directory contains the *mserver* tool which is a basic multicast data dumping tool.

Issuing:
```
cd tools
make
mserver 226.0.0.1 10.0.0.1
```
will hexdump all UDP payloads sent to group 226.0.0.1 and received on the device with the IP address 10.0.0.1. Such trafic can be injected with the knetinject driver. In order to do this, the steps below should be followed.

Configure your kni device:
```
ifconfig kni0 up
ifconfig kni0 10.0.0.1
```

Run the receiver:
```
./mserver 226.0.0.1 10.0.0.1
```

Start packet injection:
```
pcap_inject -i /dev/kni ../misc/single.pcap
```

The receiver should dump the raw data received in hex format:
```
12 bytes received
0000 | 48 65 6c 6c 6f 20 77 6f 72 6c 64 0a             | Hello world.....
12 bytes received
0000 | 48 65 6c 6c 6f 20 77 6f 72 6c 64 0a             | Hello world.....
12 bytes received
0000 | 48 65 6c 6c 6f 20 77 6f 72 6c 64 0a             | Hello world.....
```

