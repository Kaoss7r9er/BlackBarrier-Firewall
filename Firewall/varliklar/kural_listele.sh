#!/bin/bash
# Black Barrier — nftables kural listeleme betiği
# Kullanım: sudo bash kural_listele.sh

echo "═══════════════════════════════════════════"
echo "  BLACK BARRIER — GÜNCEL KURAL LİSTESİ"
echo "═══════════════════════════════════════════"

if sudo nft list table inet blackbarrier 2>/dev/null; then
    echo "═══════════════════════════════════════════"
else
    echo "[!] 'blackbarrier' tablosu henüz oluşturulmamış."
    echo "    Tablo oluşturmak için bir kural ekleyin."
    echo "═══════════════════════════════════════════"
fi
