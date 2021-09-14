# Geneve Protocol
> 15th September 2021

I was introduced to the existance of the Geneve protocol by a lectuerer in a 
Operating Systems course at uni. I thought the concept of Network Virtualisation
via Encapsulation was interesting and wanted to follow the 
[rfc8926](https://datatracker.ietf.org/doc/html/rfc8926) spec for Geneve and 
create a pseudo-driver. 

I developed it for [OpenBSD](https://www.openbsd.org/) as I wanted to do 
something different and had installed it as my daily driver on my laptop. As I
was developing C on OpenBSD I felt inclinded to follow the 
[OpenBSD Style Guide](https://man.openbsd.org/style.9). The Makefile also 
utilises the `bsd.prog.mk` src OpenBSD program which is works as its own build
system.

**This code will require refactoring**

## What is Geneve

Geneve is a Network Virtualisation Encapsulation protocol piggy backing off a 
single UDP connection. It aims to have multiple virtual devices on the single
client/network and allow for multiple tunnels to a server. A example design
of a network is as follows:

```
Taken from: 
    https://tools.ietf.org/html/rfc8926#section-2

     +---------------------+           +-------+  +------+
     | +--+  +-------+---+ |           |Transit|--|Top of|==Physical
     | |VM|--|       |   | | +------+ /|Router |  | Rack |==Servers
     | +--+  |Virtual|NIC|---|Top of|/ +-------+\/+------+
     | +--+  |Switch |   | | | Rack |\ +-------+/\+------+
     | |VM|--|       |   | | +------+ \|Transit|  |Uplink|   WAN
     | +--+  +-------+---+ |           |Router |--|      |=========>
     +---------------------+           +-------+  +------+
            Hypervisor

                 ()===================================()
                         Switch-Switch Geneve Tunnels
```

The hypervisor in this case can be a single machine that has TUN/TAP virtual
network drivers to virtual machines. The hypervisor will also have a single 
UDP connection outside the network to a destination server that the VMs can 
access.

This implementation of Geneve will require a modification to packet headers
to fit the standardised Geneve Header which is described as follows:

```
Taken from: 
    https://tools.ietf.org/html/rfc8926#section-3

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Virtual Network Identifier (VNI)       |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Variable Length Options                    |
~                                                               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Ver (2 bits):  The current version number is 0.  Packets received by
    a tunnel endpoint with an unknown version MUST be dropped.
    Transit devices interpreting Geneve packets with an unknown
    version number MUST treat them as UDP packets with an unknown
    payload.

Opt Len (6 bits):  The length of the options fields, expressed in
    four byte multiples, not including the eight byte fixed tunnel
    header.  This results in a minimum total Geneve header size of 8
    bytes and a maximum of 260 bytes.  The start of the payload
    headers can be found using this offset from the end of the base
    Geneve header.

    Transit devices MUST maintain consistent forwarding behavior
    irrespective of the value of 'Opt Len', including ECMP link
    selection.

O (1 bit):  Control packet.  This packet contains a control message.
    Control messages are sent between tunnel endpoints.  Tunnel
    endpoints MUST NOT forward the payload and transit devices MUST
    NOT attempt to interpret it.  Since control messages are less
    frequent, it is RECOMMENDED that tunnel endpoints direct these
    packets to a high priority control queue (for example, to direct
    the packet to a general purpose CPU from a forwarding ASIC or to
    separate out control traffic on a NIC).  Transit devices MUST NOT
    alter forwarding behavior on the basis of this bit, such as ECMP
    link selection.

C (1 bit):  Critical options present.  One or more options has the
    critical bit set (see Section 3.5).  If this bit is set then
    tunnel endpoints MUST parse the options list to interpret any
    critical options.  On tunnel endpoints where option parsing is not
    supported the packet MUST be dropped on the basis of the 'C' bit
    in the base header.  If the bit is not set tunnel endpoints MAY
    strip all options using 'Opt Len' and forward the decapsulated
    packet.  Transit devices MUST NOT drop packets on the basis of
    this bit.

Rsvd. (6 bits):  Reserved field, which MUST be zero on transmission
    and MUST be ignored on receipt.

Protocol Type (16 bits):  The type of the protocol data unit
    appearing after the Geneve header.  This follows the EtherType
    [ETYPES] convention; with Ethernet itself being represented by the
    value 0x6558.

Virtual Network Identifier (VNI) (24 bits):  An identifier for a
    unique element of a virtual network.  In many situations this may
    represent an L2 segment, however, the control plane defines the
    forwarding semantics of decapsulated packets.  The VNI MAY be used
    as part of ECMP forwarding decisions or MAY be used as a mechanism
    to distinguish between overlapping address spaces contained in the
    encapsulated packet when load balancing across CPUs.

Reserved (8 bits):  Reserved field which MUST be zero on transmission
    and ignored on receipt.

```

## Usage
```
usage: gnveu [-46d] [-l address] [-p port] -t 120
            -e /dev/tapX@vni
            server [port]

-4 Force IPv4
-6 Force IPv6
-d Do not daemonise
-t Idle timeout (value in seconds). 
    Closes program once idle (no traffic recieved) timeout duration
    is exceded. No timeout if negative or 0 seconds parsed.
-l Address Bind to local address, does not bind to local address 
    by default.
-p Port used as source port. Default to same port as destination.
-e /dev/tapX@vni Tunnel enter/exit point for Ethernet traffic
    for spefified tunnel device. VNI must be specified.
    VNI of 4096 sets IPv4 only
    VNI of 8192 sets IPv6 only
    Can specify multiple tunnels with multiple -e params
server The destination address if remote tunnel endpoint.
port The port used for remote tunnel endpoint. Default to 6081.
```

## How this program works
1. Parse the parameters.
2. It open the tap interface devices (Creates if doesn't exist) passed in with the `-e` parameter and sets up a read and timeout event. 
3. It creates a socket `connecting` it to the destination server and `binding` it to a local port (same as destination port if not specified) and a local address (if specified). 
4. A read and timeout event is also setup for the socket once it has been connected and binded.
5. Starts the event loop.

**In the event loop**
- If a read event is triggered for a tap device then a packet is `read -> encapsulated -> sent` to the destination server through the socket.
  - Tap packet Geneve headers are optionless and have their VNI set. Total header size is 8 bytes.
- If a read event is triggered for a socket device the a packet is `received -> decapsulated -> filtered (by VNI) -> sent` to the respected tap devices with the corresponding VNIs.
  - Socket packet Geneve headers can be between 8 to 260 bytes and must be interpreted to know how much of the front of the packet needs to be removed to correctly remove the header.
  - Non geneve packets, incorrectly formatted geneve packets or packets with no corresponding taps are silently dropped.
- If a timeout event is triggered it will close the devices file descriptor. This only happens if a event hasn't been triggered for the given timeout time (if there is one).

## Example Tap encapsulated packet with VNI 3301
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|0 0 0 0 0 0|0|0|0 0 0 0 0 0|0 1 1 0 0 1 0 1 0 1 0 1 1 0 0 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 0 1 1 1 0 0 1 0 1|0 0 0 0 0 0 0 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         PACKET PAYLOAD                        |
~                                                               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```