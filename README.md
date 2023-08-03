ipgen
=====
![screenshot](https://github.com/iij/ipgen/wiki/img/screenshot.png)

ipgen is an Interactive Packet Generator with netmap|XDP

- [Abstract](#abstract)
- [Build](#build)
  - [FreeBSD](#freebsd)
  - [Linux](#linux)
- [Caveat](#caveat)
- [Usage](#usage)

# Abstract
ipgen is a packet traffic generator that uses netmap or XDP.
It can interactively output packets of various sizes and rates, and measure how many have been dropped.

ipgen is implemented using the netmap feature of FreeBSD or the XDP feature of Linux.

AF_XDP on Linux is developed and tested on Ubuntu 21.04.
It should work on recent Fedora Linux too with some minor tweaks.


# Build

## FreeBSD
- setup FreeBSD and config kernel with NETMAP (add "device netmap" to conf/GENERIC).
- gmake, perl and libevent are required to compile.
- checkout and build
```
git clone git@github.com:iij/ipgen.git
cd ipgen
gmake depend && gmake && sudo gmake install
```
- run ipgen

## Linux
You will need libbsd and other libraries etc. See below.
```
apt install libbsd-dev clang libssl-dev libevent-dev libbpf-dev bmake
git clone https://github.com/iij/ipgen.git
cd ipgen
make depend && make && sudo make install
```
- run ipgen

Tested on Ubuntu 22.04.

## Caveat

On linux, ipgen with AF_XDP uses only the 1st hardware queue on a netowrk
adapter, so if the network adapter uses multiple hardware queues
ipgen with AF_XDP doesn't work correctly.

You can check if your network adapter, say `eth0`, uses
multiple queues by `ethtool -l eth0`.
If so you can change the number of using queues to just one by:

```
ethtool -L eth0 combined 1
```

# Usage
Please refer to the following presentation materials.

ipgen: Interactive Packet Generator for performance measurement
- in english https://github.com/iij/ipgen/wiki/materials/ipgen.pdf
- in japanese https://github.com/iij/ipgen/wiki/materials/ipgen_ja.pdf

