#!/bin/bash
# Black Barrier — nftables ile kural kaldırma betiği
# Kullanım: sudo bash kural_kaldir.sh <IP_ADRESI>

if [ -z "$1" ]; then
    echo "HATA: IP adresi belirtilmedi."
    echo "Kullanım: $0 <IP_ADRESI>"
    exit 1
fi

IP_ADRESI="$1"

# Eşleşen kuralın handle numarasını bul
HANDLE=$(sudo nft -a list chain inet blackbarrier input 2>/dev/null | grep "$IP_ADRESI" | grep -oP 'handle \K[0-9]+' | head -1)

if [ -z "$HANDLE" ]; then
    echo "[!] $IP_ADRESI için eşleşen kural bulunamadı."
    exit 1
fi

# Handle numarasıyla kuralı sil
sudo nft delete rule inet blackbarrier input handle "$HANDLE"

if [ $? -eq 0 ]; then
    echo "[✓] $IP_ADRESI engeli başarıyla kaldırıldı (nftables)."
else
    echo "[✗] Kural kaldırılırken hata oluştu."
    exit 1
fi
