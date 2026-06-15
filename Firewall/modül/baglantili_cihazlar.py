"""
Black Barrier — Bağlı Cihazlar Toplayıcısı (baglantili_cihazlar.py)
====================================================================
Firewall'a görünen yerel ağ cihazlarını iki kaynaktan birleştirir:

  1. DHCP lease (dnsmasq) — host adıyla bilinen, IP almış cihazlar
  2. ARP/neighbor tablosu  — L2 komşuları (statik IP veya manuel atama da dahil)

MAC adresi anahtarıyla deduplikasyon yapılır. Bir cihaz her iki kaynakta da
varsa kaynak='dhcp+arp' olarak işaretlenir; bu en güvenilir kayıttır.

İade edilen her cihaz:
  {
    "ip_adresi": "192.168.1.100",
    "mac_adresi": "aa:bb:cc:dd:ee:ff",
    "host_adi": "laptop-1" | None,
    "kaynak": "dhcp" | "arp" | "dhcp+arp",
    "son_gorulme": ISO-8601 timestamp | None,
    "kira_bitis": ISO-8601 | None,   # sadece DHCP kaynaklılarda
    "arayuz": "enp0s8" | None,        # ARP'tan gelirse interface bilinir
  }
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dhcp_yonetici as dhcp_yon  # type: ignore[import-not-found]

ARP_DOSYA = Path('/proc/net/arp')

# /proc/net/arp satır formatı:
# IP_address        HW_type  Flags  HW_address          Mask  Device
# 192.168.1.10      0x1      0x2    aa:bb:cc:dd:ee:ff   *     enp0s8
#
# Flags=0x0 → eski/incomplete kayıt; 0x2 → tamamlanmış komşu
_ARP_GECERLI_FLAG = '0x2'
_MAC_BOS = '00:00:00:00:00:00'


def _arp_oku() -> list[dict[str, Any]]:
    """
    /proc/net/arp dosyasını parse eder.
    Dönüş: [{"ip_adresi", "mac_adresi", "arayuz"}, ...]
    """
    if not ARP_DOSYA.exists():
        return []
    try:
        ham = ARP_DOSYA.read_text(encoding='utf-8', errors='ignore')
    except (PermissionError, OSError):
        return []

    sonuc: list[dict[str, Any]] = []
    for satir in ham.splitlines()[1:]:  # ilk satır başlık
        parcalar = satir.split()
        if len(parcalar) < 6:
            continue
        ip, _, flags, mac, _, device = parcalar[:6]
        # Sadece tamamlanmış (gerçekten görülmüş) ve geçerli MAC'i olan komşular
        if flags != _ARP_GECERLI_FLAG or mac.lower() == _MAC_BOS:
            continue
        sonuc.append({
            "ip_adresi": ip,
            "mac_adresi": mac.lower(),
            "arayuz": device,
        })
    return sonuc


def _mac_normalize(mac: str | None) -> str | None:
    """MAC adresini küçük harf + iki nokta üst üste ayırıcısıyla normalize et."""
    if not mac:
        return None
    m = mac.strip().lower().replace('-', ':')
    # Basit MAC formatı kontrolü (ek doğrulama olarak)
    if not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', m):
        return None
    return m


def cihazlari_topla() -> list[dict[str, Any]]:
    """
    DHCP lease + ARP tablosunu birleştirip cihaz listesi döndürür.
    MAC adresi anahtarı; ikisinde de bulunan cihazlar tek satıra birleşir.
    """
    simdi_iso = datetime.now(timezone.utc).isoformat()

    # MAC → cihaz kaydı sözlüğü (deduplikasyon için)
    cihazlar: dict[str, dict[str, Any]] = {}

    # 1) DHCP lease'leri
    for lease in dhcp_yon.aktif_kiralamalar():
        mac = _mac_normalize(lease.get('mac_adresi'))
        if not mac:
            continue
        cihazlar[mac] = {
            "ip_adresi": lease.get('ip_adresi'),
            "mac_adresi": mac,
            "host_adi": lease.get('host_adi'),
            "kaynak": "dhcp",
            "son_gorulme": simdi_iso,
            "kira_bitis": lease.get('kira_bitis'),
            "arayuz": lease.get('arayuz'),
        }

    # 2) ARP komşuları — DHCP'de varsa kaynak'ı 'dhcp+arp' yap, yoksa yeni satır
    for arp in _arp_oku():
        mac = _mac_normalize(arp.get('mac_adresi'))
        if not mac:
            continue
        if mac in cihazlar:
            cihazlar[mac]["kaynak"] = "dhcp+arp"
            # ARP arayüzü daha güvenilir (DHCP lease dosyasında her zaman olmaz)
            if not cihazlar[mac].get("arayuz"):
                cihazlar[mac]["arayuz"] = arp.get("arayuz")
        else:
            cihazlar[mac] = {
                "ip_adresi": arp.get("ip_adresi"),
                "mac_adresi": mac,
                "host_adi": None,
                "kaynak": "arp",
                "son_gorulme": simdi_iso,
                "kira_bitis": None,
                "arayuz": arp.get("arayuz"),
            }

    # IP'ye göre sırala (boşları sona)
    def _siralama_anahtari(c: dict[str, Any]) -> tuple:
        ip = c.get("ip_adresi") or ""
        # IPv4 octetlerine göre sırala
        try:
            parts = tuple(int(p) for p in ip.split('.'))
        except (ValueError, AttributeError):
            parts = (999, 999, 999, 999)
        return (parts,)

    return sorted(cihazlar.values(), key=_siralama_anahtari)
