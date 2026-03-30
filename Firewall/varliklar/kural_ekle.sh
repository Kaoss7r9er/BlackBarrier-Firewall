#!/bin/bash
IP_ADRESI=$1
sudo iptables -A INPUT -s $IP_ADRESI -j DROP
echo "$IP_ADRESI basariyla engellendi."
