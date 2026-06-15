"""
Black Barrier — DHCP Sunucu Yöneticisi (dhcp_yonetici.py)
==========================================================
DB'deki dhcp_ayarlari satırlarını dnsmasq config dosyasına çevirir
ve dnsmasq servisini yeniden başlatır. Lease dosyasını da parse eder.

Yaklaşım:
- /etc/dnsmasq.d/blackbarrier-dhcp.conf üretilir (ana /etc/dnsmasq.conf'a dokunulmaz)
- dnsmasq hem DHCP hem DNS yapar: LAN istemcileri için forwarding DNS resolver
  (bind-interfaces ile yalnızca LAN arayüzünde dinler, systemd-resolved ile
  çakışmaz) + panelden engellenen domainler için 'address=/domain/0.0.0.0'
  (youtube gibi çok-IP'li adresleri DNS seviyesinde engeller)
- Aktif olmayan DHCP kayıtları atlanır
- interface_adi (sistem arayüzü, örn. enp0s8) zorunlu — yoksa DHCP satırı atlanır
- BB_DHCP_DISABLED=1 ortam değişkeniyle çalıştırma devre dışı (lokal dev için)

Lease parser:
- /var/lib/misc/dnsmasq.leases formatı:
    <bitis_unix_ts> <mac> <ip> <hostname|*> <client_id|*>
"""

import os
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ── Yapılandırma ──────────────────────────────────────────────
DHCP_DEVRE_DISI = os.environ.get('BB_DHCP_DISABLED', '0') == '1'
CONFIG_YOLU = Path('/etc/dnsmasq.d/blackbarrier-dhcp.conf')
LEASE_YOLU = Path('/var/lib/misc/dnsmasq.leases')
SERVIS_ADI = 'dnsmasq'
KOMUT_TIMEOUT_SN = 8

# DNS engelleme (domain blocklist) yapılandırması.
# DNS yalnızca engellenecek domain VARSA açılır; yoksa port=0 ile DNS kapalı
# kalır (davranış değişmez, risk yok).
# BB_DNS_ARAYUZU: dnsmasq'ın DNS dinleyeceği LAN arayüzü (istemcilerin DNS'i
#   firewall'a yönlendirildiğinde bu arayüzden sorulur).
# BB_DNS_UPSTREAM: engellenmemiş sorguların iletileceği üst DNS sunucuları.
DNS_ARAYUZU = os.environ.get('BB_DNS_ARAYUZU', 'enp0s8').strip()
DNS_UPSTREAM = [
    s.strip() for s in os.environ.get('BB_DNS_UPSTREAM', '8.8.8.8,1.1.1.1').split(',')
    if s.strip()
]

# DB'deki sembolik adlara karşılık gelen sistem interface'lerini install zamanı
# bilirsen burayı doldurabilirsin; çalışma zamanında DB'deki interface_adi
# alanına bakılır. Bu sözlük yalnızca fallback olarak kullanılır.
SEMBOLIK_INTERFACE_FALLBACK: dict[str, str] = {}

_uygula_kilidi = threading.Lock()


# ══════════════════════════════════════════════════════════════
#  YARDIMCILAR
# ══════════════════════════════════════════════════════════════

def dnsmasq_kullanilabilir_mi() -> bool:
    """dnsmasq binary'si sistemde var mı?"""
    return shutil.which('dnsmasq') is not None


def _komut_calistir(args: list[str], sessiz: bool = False) -> tuple[int, str, str]:
    """subprocess.run sarmalayıcısı; args liste olmalı (komut enjeksiyon koruması)."""
    if not isinstance(args, list):
        raise TypeError("args bir liste olmalı")

    if DHCP_DEVRE_DISI:
        print(f"[dhcp-dev] {' '.join(args)}")
        return 0, '', ''

    try:
        sonuc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=KOMUT_TIMEOUT_SN,
            check=False,
        )
        if sonuc.returncode != 0 and not sessiz:
            print(f"[dhcp-hata] komut={' '.join(args)} stderr={sonuc.stderr.strip()}")
        return sonuc.returncode, sonuc.stdout, sonuc.stderr
    except FileNotFoundError:
        if not sessiz:
            print(f"[dhcp-hata] binary bulunamadı: {args[0]}")
        return -1, '', 'binary-not-found'
    except subprocess.TimeoutExpired:
        if not sessiz:
            print(f"[dhcp-hata] Timeout: {' '.join(args)}")
        return -1, '', 'timeout'
    except Exception as e:
        if not sessiz:
            print(f"[dhcp-hata] {e}")
        return -1, '', str(e)


def _interface_coz(ayar: dict[str, Any]) -> str | None:
    """
    DB satırından sistem interface adını çıkarır.
    Öncelik: ayar.interface_adi > SEMBOLIK_INTERFACE_FALLBACK[ayar.arayuz]
    """
    aday = (ayar.get('interface_adi') or '').strip()
    if aday:
        return aday
    arayuz = (ayar.get('arayuz') or '').strip()
    return SEMBOLIK_INTERFACE_FALLBACK.get(arayuz)


# ══════════════════════════════════════════════════════════════
#  KONFİG ÜRETİMİ
# ══════════════════════════════════════════════════════════════

def _config_olustur(
    ayarlar: Iterable[dict[str, Any]],
    engelli_domainler: Iterable[str] | None = None,
) -> str:
    """
    DB satırlarından dnsmasq config metnini üretir (DHCP + DNS forwarding + engelleme).

    DNS davranışı:
      - dnsmasq HER ZAMAN LAN arayüzünde forwarding DNS resolver olur
        (bind-interfaces + except-interface=lo → systemd-resolved 127.0.0.53 ile
        çakışmaz; no-resolv + server=<upstream> ile yukarı iletir).
      - engelli_domainler verilmişse her biri 'address=/domain/0.0.0.0' ile
        engellenir (domain ve TÜM alt domainleri kapsar). youtube gibi çok-IP'li
        adresleri DNS seviyesinde keser — IP listesinden bağımsız.

    Aktif olmayan veya interface_adi olmayan DHCP satırları atlanır.
    """
    domainler = [d.strip() for d in (engelli_domainler or []) if d and d.strip()]
    # DNS HER ZAMAN açık: firewall, LAN istemcileri için forwarding DNS resolver
    # olur. Engelli domainler 0.0.0.0'a çözülür, gerisi upstream'e iletilir.
    # Böylece istemci DNS'i firewall'a ayarlandığında — engelli domain olsun
    # olmasın — internet çalışır (aksi halde blocklist boşalınca DNS kopardı).
    dns_acik = True

    # DHCP aktif ayarlarını önce topla (interface dedup için)
    dhcp_kayitlari: list[dict[str, Any]] = []
    for ayar in ayarlar:
        if int(ayar.get('aktif', 0) or 0) != 1:
            continue
        iface = _interface_coz(ayar)
        havuz_bas = (ayar.get('havuz_baslangic') or '').strip()
        havuz_son = (ayar.get('havuz_bitis') or '').strip()
        if not iface or not havuz_bas or not havuz_son:
            print(f"[dhcp] '{ayar.get('arayuz')}' atlandı "
                  f"(interface_adi/havuz_baslangic/havuz_bitis eksik)")
            continue
        dhcp_kayitlari.append({**ayar, '_iface': iface})

    satirlar: list[str] = [
        "# Black Barrier — Otomatik üretildi (dhcp_yonetici.py)",
        "# Bu dosyayı elle düzenlemeyin; panel üzerinden yapılandırın.",
        "",
    ]

    # ── DNS bloğu ──────────────────────────────────────────────
    # Forwarding resolver + (varsa) domain blocklist. Yalnızca LAN arayüzünde
    # dinle (bind-interfaces) → systemd-resolved (127.0.0.53) ile çakışmaz.
    satirlar += [
        "# DNS forwarding resolver (LAN istemcileri için) + domain engelleme.",
        "# Sadece LAN arayüzünde dinle; systemd-resolved (127.0.0.53) ile çakışmaz.",
        "bind-interfaces",
        "except-interface=lo",
        "no-resolv",
        # TTL sınırı: bir domaini engelleyip kaldırınca (veya tam tersi) değişikliğin
        # hızlı yansıması için istemcilere verilen TTL en fazla 30 sn. Aksi halde
        # engel kaldırılınca istemci gerçek IP'yi uzun süre (youtube TTL ~300sn)
        # cache'ler ve tekrar engellenince eski IP'yle erişmeye devam eder.
        "max-ttl=30",
    ]
    for up in (DNS_UPSTREAM or ['8.8.8.8']):
        satirlar.append(f"server={up}")
    satirlar.append("")

    satirlar += [
        "# Lease veritabanı (default; explicit yazıyoruz)",
        f"dhcp-leasefile={LEASE_YOLU}",
        "",
    ]

    # ── interface= satırları (DHCP arayüzleri + gerekiyorsa DNS arayüzü), tekilleştirilmiş ──
    arayuzler: list[str] = []
    for k in dhcp_kayitlari:
        if k['_iface'] not in arayuzler:
            arayuzler.append(k['_iface'])
    if dns_acik and DNS_ARAYUZU and DNS_ARAYUZU not in arayuzler:
        arayuzler.append(DNS_ARAYUZU)
    for iface in arayuzler:
        satirlar.append(f"interface={iface}")
    if arayuzler:
        satirlar.append("")

    # ── DNS blocklist ──────────────────────────────────────────
    if domainler:
        satirlar.append("# === Engellenen domainler (DNS) ===")
        for d in domainler:
            # Hem IPv4 (A → 0.0.0.0) hem IPv6 (AAAA → ::) kaydını engelle.
            # Sadece 0.0.0.0 verilirse istemci IPv6 üzerinden siteye ulaşabilir,
            # engelleme delinir. address=/domain/... domain + TÜM alt domainleri kapsar.
            satirlar.append(f"address=/{d}/0.0.0.0")
            satirlar.append(f"address=/{d}/::")
        satirlar.append("")

    # ── DHCP havuzları ─────────────────────────────────────────
    for k in dhcp_kayitlari:
        iface = k['_iface']
        havuz_bas = (k.get('havuz_baslangic') or '').strip()
        havuz_son = (k.get('havuz_bitis') or '').strip()
        maske = (k.get('alt_ag_maskesi') or '').strip()
        kira = int(k.get('kira_suresi', 86400) or 86400)
        satirlar.append(f"# === DHCP: {k.get('arayuz')} ({iface}) ===")
        if maske:
            satirlar.append(f"dhcp-range={iface},{havuz_bas},{havuz_son},{maske},{kira}")
        else:
            satirlar.append(f"dhcp-range={iface},{havuz_bas},{havuz_son},{kira}")

        gateway = (k.get('ag_gecidi') or '').strip()
        if gateway:
            satirlar.append(f"dhcp-option={iface},3,{gateway}")

        dns = (k.get('dns_sunuculari') or '').strip()
        if dns:
            dns_temiz = ','.join(s.strip() for s in dns.split(',') if s.strip())
            if dns_temiz:
                satirlar.append(f"dhcp-option={iface},6,{dns_temiz}")
        satirlar.append("")

    if not dhcp_kayitlari:
        satirlar.append("# Aktif DHCP havuzu yok — dnsmasq yalnızca DNS resolver modunda")

    return "\n".join(satirlar) + "\n"


def _config_yaz(icerik: str) -> bool:
    """Üretilen config'i diske yazar."""
    if DHCP_DEVRE_DISI:
        print(f"[dhcp-dev] Config yazılacaktı: {CONFIG_YOLU}")
        print(icerik)
        return True
    try:
        CONFIG_YOLU.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_YOLU.write_text(icerik, encoding='utf-8')
        os.chmod(CONFIG_YOLU, 0o644)
        return True
    except PermissionError:
        print(f"[dhcp-hata] {CONFIG_YOLU} yazılamadı (root yetkisi gerekli)")
        return False
    except OSError as e:
        print(f"[dhcp-hata] Config yazma hatası: {e}")
        return False


def _servis_yeniden_baslat() -> bool:
    """dnsmasq servisini yeniden başlatır."""
    kod, _, _ = _komut_calistir(['systemctl', 'restart', f'{SERVIS_ADI}.service'])
    return kod == 0


# ══════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════

def tum_dhcp_yapilandirmasini_uygula(
    ayarlar: Iterable[dict[str, Any]],
    engelli_domainler: Iterable[str] | None = None,
) -> tuple[bool, int]:
    """
    DB'deki tüm DHCP ayarlarını (ve verilmişse DNS engelleme domainlerini)
    dnsmasq config dosyasına yazıp servisi yeniden başlatır.

    Döndürür: (basarili_mi, uygulanan_yapilandirma_sayisi)
    """
    with _uygula_kilidi:
        ayar_listesi = list(ayarlar)
        icerik = _config_olustur(ayar_listesi, engelli_domainler)

        if not _config_yaz(icerik):
            return False, 0

        aktif_sayi = sum(1 for a in ayar_listesi if int(a.get('aktif', 0) or 0) == 1)

        if not dnsmasq_kullanilabilir_mi() and not DHCP_DEVRE_DISI:
            print("[dhcp] dnsmasq binary'si bulunamadı; config yazıldı ama servis yenilenmedi.")
            return True, aktif_sayi

        basarili = _servis_yeniden_baslat()
        if basarili:
            print(f"[dhcp] dnsmasq yeniden başlatıldı ({aktif_sayi} aktif yapılandırma)")
        else:
            print("[dhcp] dnsmasq yeniden başlatılamadı; 'journalctl -u dnsmasq' ile inceleyin")
        return basarili, aktif_sayi


# ══════════════════════════════════════════════════════════════
#  LEASE PARSER
# ══════════════════════════════════════════════════════════════

def aktif_kiralamalar(interface_adi: str | None = None) -> list[dict[str, Any]]:
    """
    /var/lib/misc/dnsmasq.leases dosyasını okur, kiralamaları döndürür.
    interface_adi verilmezse tüm kiralamalar; verilirse o interface'in subnet'iyle
    eşleşenler döndürülür (lease dosyasında interface bilgisi yok, IP'den eşleştirme
    çağıran tarafa bırakılır — şimdilik tümü döner).

    Lease satır formatı: <bitis_ts> <mac> <ip> <hostname> <client_id>
    """
    if not LEASE_YOLU.exists():
        return []

    try:
        ham = LEASE_YOLU.read_text(encoding='utf-8', errors='ignore')
    except (PermissionError, OSError) as e:
        print(f"[dhcp] Lease dosyası okunamadı: {e}")
        return []

    simdi = datetime.now(timezone.utc).timestamp()
    sonuc: list[dict[str, Any]] = []
    for satir in ham.splitlines():
        parcalar = satir.strip().split()
        if len(parcalar) < 4:
            continue
        try:
            bitis_ts = int(parcalar[0])
        except ValueError:
            continue
        mac = parcalar[1]
        ip = parcalar[2]
        host = parcalar[3] if parcalar[3] != '*' else None

        durum = 'aktif' if bitis_ts > simdi else 'suresi_dolmus'
        bitis_iso = datetime.fromtimestamp(bitis_ts, tz=timezone.utc).isoformat()

        sonuc.append({
            'ip_adresi': ip,
            'mac_adresi': mac,
            'host_adi': host,
            'kira_bitis': bitis_iso,
            'kira_baslangic': None,
            'durum': durum,
            'arayuz': interface_adi,
        })

    return sonuc
