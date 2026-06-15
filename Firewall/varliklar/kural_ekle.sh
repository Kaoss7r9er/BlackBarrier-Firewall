#!/bin/bash
# Black Barrier — nftables ile kural ekleme betiği
# Kullanım: sudo bash kural_ekle.sh <IP_ADRESI>

if [ -z "$1" ]; then
    echo "HATA: IP adresi belirtilmedi."
    echo "Kullanım: $0 <IP_ADRESI>"
    exit 1
fi

IP_ADRESI="$1"

# nftables tablosu ve zinciri yoksa oluştur
sudo nft add table inet blackbarrier 2>/dev/null
sudo nft add chain inet blackbarrier input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null

# Engelleme kuralını ekle
sudo nft add rule inet blackbarrier input ip saddr "$IP_ADRESI" drop

if [ $? -eq 0 ]; then
    echo "[✓] $IP_ADRESI başarıyla engellendi (nftables)."
else
    echo "[✗] Kural eklenirken hata oluştu."
    exit 1
fi
