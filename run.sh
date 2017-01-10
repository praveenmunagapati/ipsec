#!/bin/bash

echo "PacketNgin IPsec ver2.0"
VMID=$(create -c 1 -m 0xc00000 -s 0x800000 -n dev=eth0,pool=0x400000 -n dev=eth0,pool=0x400000 | sed -n 2p)
upload $VMID ipsec
# start $VMID
# 
# stdin $VMID 0 "ip add eth0 192.168.100.254"
# stdin $VMID 0 "ip add eth1 10.0.0.1"
# stdin $VMID 0 "route add 192.168.200.0 gw 10.0.0.2 dev eth1"
# 
# stdin $VMID 0 "ip"
# stdin $VMID 0 "route"
