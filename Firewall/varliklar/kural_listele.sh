#!/bin/bash
echo "---GÜNCEL ENGELLEME LİSTESİ---"
sudo iptables -L INPUT -n --line-numbers | grep DROP
echo "------------------------------------"
