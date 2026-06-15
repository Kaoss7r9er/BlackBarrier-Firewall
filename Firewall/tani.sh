#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  BLACK BARRIER — Ağ Tanı ve Onarım Aracı (tani.sh)
#
#  Bu betik şunları yapar:
#    1. Network durumunu raporlar (interfaces, routes, IP forwarding)
#    2. nftables + iptables (legacy) çakışmasını tespit eder
#    3. --onar bayrağıyla iptables katmanını temizler ve nftables'ı
#       BlackBarrier servisinden yeniden yükler
#
#  Kullanım:
#    sudo bash tani.sh           # Sadece rapor (güvenli)
#    sudo bash tani.sh --onar    # Bozuk iptables state'i temizle ve resync
# ══════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

baslik() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}"; }
ok()     { echo -e "${GREEN}✓${NC} $1"; }
warn()   { echo -e "${YELLOW}⚠${NC} $1"; }
err()    { echo -e "${RED}✗${NC} $1"; }
info()   { echo -e "${DIM}  $1${NC}"; }

ONAR=0
for arg in "$@"; do
    case "$arg" in
        --onar|--fix) ONAR=1 ;;
        --help|-h)
            sed -n '2,17p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    err "Bu betik root yetkisi ister: sudo bash tani.sh [--onar]"
    exit 1
fi

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║   BLACK BARRIER — Ağ Tanı ve Onarım Aracı       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════
#  1. SİSTEM BİLGİSİ
# ══════════════════════════════════════════════════════════════
baslik "Sistem"
echo -e "  ${DIM}Kernel: $(uname -r)${NC}"
echo -e "  ${DIM}Tarih:  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
if command -v lsb_release >/dev/null; then
    echo -e "  ${DIM}OS:     $(lsb_release -d | cut -f2)${NC}"
fi

# ══════════════════════════════════════════════════════════════
#  2. AĞ ARAYÜZLERİ
# ══════════════════════════════════════════════════════════════
baslik "Ağ Arayüzleri"
ip -br addr show | grep -v '^lo' | while read -r line; do
    iface=$(echo "$line" | awk '{print $1}')
    state=$(echo "$line" | awk '{print $2}')
    if [ "$state" = "UP" ]; then
        ok "$line"
    else
        warn "$line"
    fi
done

# ══════════════════════════════════════════════════════════════
#  3. ROUTING TABLOSU
# ══════════════════════════════════════════════════════════════
baslik "Routing Tablosu"
ip route show | while read -r r; do
    if [[ "$r" == default* ]]; then
        echo -e "  ${BOLD}${CYAN}→ ${r}${NC}"
    else
        echo -e "  ${DIM}  ${r}${NC}"
    fi
done

DEFAULT_GW=$(ip route show default 2>/dev/null | awk '{print $3}' | head -1)
DEFAULT_DEV=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
if [ -z "$DEFAULT_GW" ]; then
    err "Varsayılan gateway yok — sistem dışarı çıkamaz"
else
    info "Varsayılan: $DEFAULT_GW ($DEFAULT_DEV üzerinden)"
fi

# ══════════════════════════════════════════════════════════════
#  4. IP FORWARDING
# ══════════════════════════════════════════════════════════════
baslik "IP Forwarding"
FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$FORWARD" = "1" ]; then
    ok "net.ipv4.ip_forward = 1 (forwarding aktif)"
else
    err "net.ipv4.ip_forward = 0 (forwarding KAPALI — gateway olarak çalışmaz)"
    if [ "$ONAR" = "1" ]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-blackbarrier.conf
        ok "forwarding açıldı (kalıcı)"
    fi
fi

# ══════════════════════════════════════════════════════════════
#  5. DNS ÇÖZÜMLEMESİ
# ══════════════════════════════════════════════════════════════
baslik "DNS Çözümleme"
if getent hosts google.com >/dev/null 2>&1; then
    ok "google.com çözümlenebiliyor"
else
    err "DNS çözümleme başarısız (/etc/resolv.conf kontrol edin)"
    info "İçerik: $(cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | head -3 | tr '\n' ' ')"
fi

# ══════════════════════════════════════════════════════════════
#  6. PING TESTLERİ
# ══════════════════════════════════════════════════════════════
baslik "Bağlantı Testleri"
if [ -n "$DEFAULT_GW" ]; then
    if ping -c1 -W2 "$DEFAULT_GW" >/dev/null 2>&1; then
        ok "Gateway ($DEFAULT_GW) yanıt veriyor"
    else
        err "Gateway ($DEFAULT_GW) PING yanıt vermiyor"
    fi
fi
if ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
    ok "İnternet erişimi var (8.8.8.8 yanıt veriyor)"
else
    err "İnternet erişimi YOK (8.8.8.8 yanıt vermiyor)"
fi

# ══════════════════════════════════════════════════════════════
#  7. NFTABLES DURUMU
# ══════════════════════════════════════════════════════════════
baslik "nftables Durumu"
if ! command -v nft >/dev/null; then
    err "nft binary bulunamadı"
else
    if systemctl is-active --quiet nftables; then
        ok "nftables servisi aktif"
    else
        warn "nftables servisi aktif değil"
    fi

    # blackbarrier tablosu var mı?
    if nft list table inet blackbarrier &>/dev/null; then
        bb_kural_sayisi=$(nft list table inet blackbarrier 2>/dev/null | grep -c -E '^\s+(ip|tcp|udp|icmp|meta)' || echo 0)
        ok "inet blackbarrier tablosu mevcut ($bb_kural_sayisi kural)"
    else
        warn "inet blackbarrier tablosu YOK — BlackBarrier servisi çalışmıyor olabilir"
    fi

    # NAT tablosu var mı?
    if nft list table ip bb_nat &>/dev/null; then
        ok "ip bb_nat (NAT) tablosu mevcut"
    else
        warn "ip bb_nat tablosu YOK — masquerade/DNAT çalışmaz"
    fi
fi

# ══════════════════════════════════════════════════════════════
#  8. IPTABLES (LEGACY) ÇAKIŞMASI
# ══════════════════════════════════════════════════════════════
baslik "iptables Çakışma Kontrolü"
# Ubuntu'da iptables aslında iptables-nft alternative. Eğer iptables -L ile
# yazılan kurallar varsa, nftables tablosunda gözükür ve karışıklık yaratır.
if command -v iptables >/dev/null; then
    IPT_FILTER=$(iptables -S 2>/dev/null | grep -v '^-P' | wc -l)
    IPT_NAT=$(iptables -t nat -S 2>/dev/null | grep -v '^-P' | wc -l)
    IPT_TOPLAM=$((IPT_FILTER + IPT_NAT))

    if [ "$IPT_TOPLAM" -gt 0 ]; then
        warn "iptables katmanında $IPT_TOPLAM kural var (nftables ile çakışabilir):"
        iptables -S 2>/dev/null | grep -v '^-P' | sed 's/^/  /' | head -10
        iptables -t nat -S 2>/dev/null | grep -v '^-P' | sed 's/^/  [nat] /' | head -5

        if [ "$ONAR" = "1" ]; then
            warn "→ iptables katmanı temizleniyor..."
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -t mangle -F 2>/dev/null
            iptables -t mangle -X 2>/dev/null
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            ok "iptables katmanı temizlendi"
        else
            info "Onarmak için: sudo bash tani.sh --onar"
        fi
    else
        ok "iptables katmanında ekstra kural yok"
    fi
fi

# ══════════════════════════════════════════════════════════════
#  9. BLACKBARRIER SERVİS DURUMU
# ══════════════════════════════════════════════════════════════
baslik "BlackBarrier Servis Durumu"
for svc in blackbarrier blackbarrier-paket-dinleyici dnsmasq nftables; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "$svc → aktif"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        warn "$svc → enabled ama çalışmıyor"
    else
        info "$svc → kurulu/enabled değil"
    fi
done

# ══════════════════════════════════════════════════════════════
#  10. ONARIM: nftables resync
# ══════════════════════════════════════════════════════════════
if [ "$ONAR" = "1" ]; then
    baslik "BlackBarrier Servisini Yeniden Başlatma"
    info "blackbarrier.service restart edilecek — lifespan startup'ta DB'den"
    info "tüm filter/NAT kurallarını ve dnsmasq config'ini yeniden uygular."
    systemctl restart blackbarrier 2>/dev/null && ok "blackbarrier yeniden başlatıldı" || warn "blackbarrier başlatılamadı (servis kurulu mu?)"
    systemctl restart blackbarrier-paket-dinleyici 2>/dev/null && ok "paket dinleyici yeniden başlatıldı" || true

    # Onarım sonrası kısa bekleme + tekrar ping testi
    sleep 2
    baslik "Onarım Sonrası Doğrulama"
    if ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
        ok "İnternet erişimi geri geldi 🎉"
    else
        err "İnternet hâlâ yok — şunları kontrol edin:"
        echo -e "${DIM}  1. sudo nft list ruleset${NC}"
        echo -e "${DIM}  2. sudo journalctl -u blackbarrier -n 30${NC}"
        echo -e "${DIM}  3. ip route show${NC}"
        echo -e "${DIM}  4. WAN interface'i UP mı? ip -br link show${NC}"
    fi
fi

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
if [ "$ONAR" = "1" ]; then
    echo -e "  ${GREEN}Tanı + onarım tamamlandı.${NC}"
else
    echo -e "  ${DIM}Yukarıdaki raporu inceleyin. Bozukluk varsa:${NC}"
    echo -e "  ${YELLOW}sudo bash tani.sh --onar${NC}"
fi
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
