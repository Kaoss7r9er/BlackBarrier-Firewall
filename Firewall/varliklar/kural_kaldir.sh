#!/bin/bash
IP_ADRESI=$1
sudo iptables -D INPUT -s $IP_ADRESI -j DROP
echo "$IP_ADRESI engeli basariyla kaldirildi."
