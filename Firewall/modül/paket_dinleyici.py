"""
Black Barrier — Scapy Paket Dinleyici (paket_dinleyici.py)
============================================================
Wireshark/tcpdump altyapısı olan libpcap ile gerçek paket capturing.
nft log + journalctl yaklaşımının yerine geçer (rate limit yok,
TCP bayrakları/TTL/seq numbers gibi detaylı bilgi yakalar).

Mimari:
  Network Interface (enp0s8 vs.)
        |
        v
    [Scapy sniff()  — main thread, blocking]
        |
        v
    paket_callback() -> queue (thread-safe deque)
        |
        v
    [DB writer thread — her N sn'de batch insert]
        |
        v
    trafik_kayitlari tablosu
        |
        v
    [WebSocket /api/ws/trafik — polling, mevcut]
        |
        v
    Panel canlı tablo

Ortam değişkenleri:
  BB_DINLEME_ARAYUZU   Dinlenecek interface (default: enp0s8)
                       Birden çoksa virgülle ayır: "enp0s8,enp0s3"
                       "any" yazarsan tüm interfaces (libpcap özelliği)
  BB_BPF_FILTRESI      Berkeley Packet Filter (default: "ip")
                       Örnek: "tcp port 80", "not arp"
  BB_BATCH_BOYUTU      DB batch insert boyutu (default: 100)
  BB_BATCH_BEKLEME     Batch için max bekleme süresi (default: 0.5 sn)
  BB_PAKET_DEVRE_DISI  1 ise sniff'i çalıştırma (dev modu için)
"""

import ipaddress
import os
import signal
import sys
import threading
import time
from collections import deque
from pathlib import Path
from types import FrameType
from typing import Any, Optional

# Proje kök → sys.path
PROJE_KOK = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJE_KOK))

import db_yonetici as db  # noqa: E402

# ── Yapılandırma ──────────────────────────────────────────────
DINLEME_ARAYUZU = os.environ.get('BB_DINLEME_ARAYUZU', 'enp0s8').strip()
# Capture seviyesinde HER ŞEYİ yakala (yönetim trafiği dahil). Yönetim (8000/22)
# trafiği panelde "Yönetim trafiğini gizle" filtresiyle VARSAYILAN olarak gizlenir,
# ama capture'da tutulur ki istenirse açılıp incelenebilsin.
BPF_FILTRESI = os.environ.get('BB_BPF_FILTRESI', 'ip').strip()
BATCH_BOYUTU = int(os.environ.get('BB_BATCH_BOYUTU', '100'))
BATCH_BEKLEME = float(os.environ.get('BB_BATCH_BEKLEME', '0.5'))
DEVRE_DISI = os.environ.get('BB_PAKET_DEVRE_DISI', '0') == '1'

# Çoklu interface desteği
if ',' in DINLEME_ARAYUZU:
    ARAYUZLER = [x.strip() for x in DINLEME_ARAYUZU.split(',') if x.strip()]
else:
    ARAYUZLER = [DINLEME_ARAYUZU]

# ── Paket kuyruğu (thread-safe deque + lock) ───────────────────
_KUYRUK: deque = deque()
_KUYRUK_KILIT = threading.Lock()
_CALISIYOR = True

# ── Engelleme kuralı eşleştirme (görsel "engellendi" etiketi) ──
# scapy paketi arayüz INGRESS'te (netfilter karar vermeden önce) yakalar; bu
# yüzden bir paket gerçekte drop edilse bile bu pasif dinleyici onu görür ve
# default 'izin_ver' olarak işaretlerdi. Kullanıcı "engelledim ama akışta hâlâ
# görünüyor" diye karışıyordu. Çözüm: yakalanan paketi DB'deki aktif engelleme
# (engelle/reddet) kurallarıyla eşleştirip eylem'i 'engelle' olarak işaretle.
# Bu yalnızca GÖRSEL bir etikettir — gerçek drop'u nftables yapar.
_BLOK_KURALLAR: list[dict[str, Any]] = []
_BLOK_KILIT = threading.Lock()
BLOK_YENILEME_SN = float(os.environ.get('BB_BLOK_YENILEME_SN', '10'))

# ── DNS snooping: ip → domain önbelleği ("Info / Site" sütunu için) ──
# Firewall DNS sunucusu olduğu için istemcilerin DNS yanıtlarını görürüz.
# 'youtube.com → 142.250.x.x' eşleşmesini yakalayıp önbelleğe alırız; sonra o
# IP'ye giden/gelen trafiği "youtube.com" olarak etiketleriz. Küçük işletmeler
# tek tek IP'ye bakmak yerine doğrudan site adını görür.
_DNS_KESHI: dict[str, str] = {}
_DNS_KILIT = threading.Lock()
DNS_KESHI_MAX = int(os.environ.get('BB_DNS_KESHI_MAX', '5000'))

# İstatistik (debug için)
_TOPLAM_PAKET = 0
_TOPLAM_DB_YAZILAN = 0
_STAT_BASLANGIC = time.time()


# ══════════════════════════════════════════════════════════════
#  SCAPY IMPORT (lazy — hata mesajını anlaşılır yap)
# ══════════════════════════════════════════════════════════════
try:
    # ARP eklemeden import et — IPv4 ile yetiniyoruz, ek sürpriz yok
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # type: ignore[import-not-found]
    from scapy.layers.dns import DNS, DNSRR  # type: ignore[import-not-found]
    from scapy.packet import Packet  # type: ignore[import-not-found]
except ImportError as e:
    print(f"[paket-dinleyici] HATA: scapy yüklü değil: {e}", flush=True)
    print("[paket-dinleyici] Kurulum: source .venv/bin/activate && pip install scapy", flush=True)
    sys.exit(1)


# ══════════════════════════════════════════════════════════════
#  ENGELLEME KURALI EŞLEŞTİRME
# ══════════════════════════════════════════════════════════════

def blok_kurallarini_yenile() -> None:
    """DB'deki aktif engelleme (engelle/reddet) kurallarını önbelleğe alır."""
    global _BLOK_KURALLAR
    try:
        kurallar = db.kurallari_getir(sadece_aktif=True)
    except Exception as e:
        print(f"[paket-dinleyici] engelleme kuralları yenilenemedi: {e}", flush=True)
        return
    blok = [k for k in kurallar if (k.get('eylem') or '') in ('engelle', 'reddet')]
    with _BLOK_KILIT:
        _BLOK_KURALLAR = blok


def _ip_eslesir(paket_ip: Optional[str], kural_ip: Optional[str]) -> bool:
    """Kural IP'si None ise her IP eşleşir. CIDR ('a.b.c.d/n') veya tek IP."""
    if not kural_ip:
        return True
    if not paket_ip:
        return False
    try:
        if '/' in kural_ip:
            return ipaddress.ip_address(paket_ip) in ipaddress.ip_network(kural_ip, strict=False)
        return paket_ip == kural_ip
    except ValueError:
        return False


def _port_eslesir(paket_port: Optional[int], kural_port: Optional[str]) -> bool:
    """Kural portu None ise her port eşleşir. '80' veya aralık '8000-8090'."""
    if not kural_port:
        return True
    s = str(kural_port).strip()
    if '-' in s:
        try:
            lo_s, hi_s = s.split('-', 1)
            lo, hi = int(lo_s), int(hi_s)
        except ValueError:
            return False
        return paket_port is not None and lo <= paket_port <= hi
    return paket_port is not None and str(paket_port) == s


def _dns_snoop(pkt: 'Packet') -> None:
    """
    DNS yanıtındaki A/AAAA kayıtlarını ip→domain önbelleğine ekler.
    Yalnızca yanıt (qr=1) ve cevap içeren paketler işlenir. Çağıran taraf bunu
    sadece UDP 53 paketleri için çağırmalı (hot-path'i şişirmemek için).
    """
    try:
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        if getattr(dns, 'qr', 0) != 1 or getattr(dns, 'ancount', 0) == 0:
            return
        qd = getattr(dns, 'qd', None)
        if not qd:
            return
        qname = bytes(qd.qname).decode('utf-8', 'ignore').rstrip('.')
        if not qname:
            return
        with _DNS_KILIT:
            for i in range(int(dns.ancount)):
                try:
                    rr = dns.an[i]
                except Exception:
                    break
                if getattr(rr, 'type', None) in (1, 28):  # A=1, AAAA=28
                    ip = str(rr.rdata)
                    if ip and ip not in ('0.0.0.0', '::'):
                        _DNS_KESHI[ip] = qname
            # Boyut sınırı: aşılırsa en eski ~%20'yi at (insertion order)
            if len(_DNS_KESHI) > DNS_KESHI_MAX:
                for k in list(_DNS_KESHI)[:max(1, DNS_KESHI_MAX // 5)]:
                    _DNS_KESHI.pop(k, None)
    except Exception:
        pass  # snooping en iyi-çaba; capture'ı asla bozma


def _info_bul(kayit: dict[str, Any]) -> Optional[str]:
    """Kaydın hedef ya da kaynak IP'sine karşılık gelen domaini döndürür."""
    with _DNS_KILIT:
        return _DNS_KESHI.get(kayit.get('hedef_ip') or '') \
            or _DNS_KESHI.get(kayit.get('kaynak_ip') or '')


def _blok_eslesmesi(kayit: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Kaydın eşleştiği ilk aktif engelleme kuralını döndürür (yoksa None)."""
    with _BLOK_KILIT:
        kurallar = _BLOK_KURALLAR
    for k in kurallar:
        proto = (k.get('protokol') or 'herhangi').lower()
        if proto != 'herhangi' and proto != kayit.get('protokol'):
            continue
        if not _ip_eslesir(kayit.get('kaynak_ip'), k.get('kaynak_ip')):
            continue
        if not _ip_eslesir(kayit.get('hedef_ip'), k.get('hedef_ip')):
            continue
        if not _port_eslesir(kayit.get('kaynak_port'), k.get('kaynak_port')):
            continue
        if not _port_eslesir(kayit.get('hedef_port'), k.get('hedef_port')):
            continue
        return k
    return None


# ══════════════════════════════════════════════════════════════
#  PAKET PARSE
# ══════════════════════════════════════════════════════════════

def paket_to_kayit(pkt: 'Packet', arayuz: str) -> Optional[dict[str, Any]]:
    """
    Scapy paketinden trafik_kayitlari için bir dict çıkarır.
    IP olmayan paketler (ARP, IPv6) None döner.
    """
    if IP not in pkt:
        return None

    ip = pkt[IP]
    kayit: dict[str, Any] = {
        'kural_id': None,
        'eylem': 'izin_ver',           # Scapy passive dinleyici; firewall kararı görmüyor
        'protokol': 'herhangi',
        'kaynak_ip': ip.src,
        'kaynak_port': None,
        'hedef_ip': ip.dst,
        'hedef_port': None,
        'arayuz': arayuz,
        'paket_boyutu': len(pkt),
        'tcp_bayraklari': None,
        'ttl': int(ip.ttl) if hasattr(ip, 'ttl') else None,
        'aciklama': 'pcap',
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        kayit['protokol'] = 'tcp'
        kayit['kaynak_port'] = int(tcp.sport)
        kayit['hedef_port'] = int(tcp.dport)
        # scapy.flags → string ('S', 'SA', 'F', 'R', 'PA' vs.)
        kayit['tcp_bayraklari'] = str(tcp.flags) if tcp.flags else None
    elif UDP in pkt:
        udp = pkt[UDP]
        kayit['protokol'] = 'udp'
        kayit['kaynak_port'] = int(udp.sport)
        kayit['hedef_port'] = int(udp.dport)
    elif ICMP in pkt:
        kayit['protokol'] = 'icmp'
    # Diğer protokoller (GRE, ESP vs.) 'herhangi' olarak kalır

    return kayit


def paket_geldi(pkt: 'Packet', arayuz: str) -> None:
    """Sniff callback'i. Paketi parse edip kuyruğa atar (hızlı dönmeli)."""
    global _TOPLAM_PAKET
    kayit = paket_to_kayit(pkt, arayuz)
    if kayit is None:
        return
    # DNS yanıtıysa (UDP 53) ip→domain önbelleğini doldur (snooping)
    if kayit['protokol'] == 'udp' and (kayit['kaynak_port'] == 53 or kayit['hedef_port'] == 53):
        _dns_snoop(pkt)
    # "Info / Site": IP'ye karşılık gelen domaini etiketle
    kayit['info'] = _info_bul(kayit)
    # Aktif bir engelleme kuralıyla eşleşiyorsa görsel olarak 'engelle' işaretle
    kural = _blok_eslesmesi(kayit)
    if kural is not None:
        kayit['eylem'] = (kural.get('eylem') or 'engelle')
        kayit['kural_id'] = kural.get('id')
        kayit['aciklama'] = 'engellendi'
    with _KUYRUK_KILIT:
        _KUYRUK.append(kayit)
        _TOPLAM_PAKET += 1


# ══════════════════════════════════════════════════════════════
#  DB YAZICI THREAD
# ══════════════════════════════════════════════════════════════

def db_yazici_dongusu() -> None:
    """
    Her BB_BATCH_BEKLEME sn'de kuyruğu boşaltır ve DB'ye batch insert yapar.
    Tek bir transaction'da N kayıt yazar → sqlite için ideal performans.
    """
    global _TOPLAM_DB_YAZILAN
    son_stat = time.time()
    son_blok_yenileme = time.time()

    while _CALISIYOR:
        time.sleep(BATCH_BEKLEME)

        # Engelleme kurallarını periyodik yenile (panelden kural ekleyince
        # birkaç sn içinde "engellendi" etiketi devreye girsin)
        if time.time() - son_blok_yenileme > BLOK_YENILEME_SN:
            blok_kurallarini_yenile()
            son_blok_yenileme = time.time()

        batch: list[dict[str, Any]] = []
        with _KUYRUK_KILIT:
            # En fazla BATCH_BOYUTU kayıt al
            while _KUYRUK and len(batch) < BATCH_BOYUTU:
                batch.append(_KUYRUK.popleft())

        if not batch:
            continue

        try:
            yazilan = db.trafik_kayitlarini_batch_ekle(batch)
            _TOPLAM_DB_YAZILAN += yazilan
        except Exception as e:
            print(f"[paket-dinleyici] DB batch insert hatası: {e}", flush=True)
            # Kayıtları geri kuyruğa koy → bir sonraki turda tekrar dene
            with _KUYRUK_KILIT:
                _KUYRUK.extendleft(reversed(batch))

        # Her 30sn'de bir istatistik bas
        simdi = time.time()
        if simdi - son_stat > 30:
            sure = simdi - _STAT_BASLANGIC
            paket_hizi = _TOPLAM_PAKET / sure if sure > 0 else 0
            db_hizi = _TOPLAM_DB_YAZILAN / sure if sure > 0 else 0
            with _KUYRUK_KILIT:
                kuyruk_dolulugu = len(_KUYRUK)
            print(f"[paket-dinleyici] istatistik: "
                  f"{_TOPLAM_PAKET} paket alındı ({paket_hizi:.1f}/sn), "
                  f"{_TOPLAM_DB_YAZILAN} DB'ye yazıldı ({db_hizi:.1f}/sn), "
                  f"kuyrukta {kuyruk_dolulugu} bekliyor",
                  flush=True)
            son_stat = simdi

    # Çıkışta son batch'i de yaz
    with _KUYRUK_KILIT:
        kalan = list(_KUYRUK)
        _KUYRUK.clear()
    if kalan:
        try:
            db.trafik_kayitlarini_batch_ekle(kalan)
            print(f"[paket-dinleyici] çıkışta {len(kalan)} kayıt yazıldı.", flush=True)
        except Exception as e:
            print(f"[paket-dinleyici] çıkış batch'i hata: {e}", flush=True)


# ══════════════════════════════════════════════════════════════
#  SNIFF THREAD (bir interface başına)
# ══════════════════════════════════════════════════════════════

def sniff_thread(arayuz: str) -> None:
    """
    scapy.sniff() çağrısı — main thread'i bloklamasın diye thread'de.
    sniff() infinite loop'tur, store=False ile RAM şişmez.
    """
    print(f"[paket-dinleyici] '{arayuz}' dinlemeye başlanıyor "
          f"(filter='{BPF_FILTRESI}', batch={BATCH_BOYUTU}, bekleme={BATCH_BEKLEME}sn)",
          flush=True)
    try:
        sniff(
            iface=arayuz if arayuz != 'any' else None,
            prn=lambda pkt: paket_geldi(pkt, arayuz),
            store=False,
            filter=BPF_FILTRESI,
            stop_filter=lambda _pkt: not _CALISIYOR,
        )
    except PermissionError:
        print(f"[paket-dinleyici] HATA: '{arayuz}' için root yetkisi gerekli (raw socket).", flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"[paket-dinleyici] '{arayuz}' sniff hatası: {e}", flush=True)


# ══════════════════════════════════════════════════════════════
#  SİNYAL İŞLEYİCİ
# ══════════════════════════════════════════════════════════════

def _sinyal_isleyici(signum: int, _frame: Optional[FrameType]) -> None:
    global _CALISIYOR
    print(f"[paket-dinleyici] Sinyal {signum} alındı, kapatılıyor...", flush=True)
    _CALISIYOR = False


# ══════════════════════════════════════════════════════════════
#  ANA
# ══════════════════════════════════════════════════════════════

def ana() -> int:
    signal.signal(signal.SIGTERM, _sinyal_isleyici)
    signal.signal(signal.SIGINT, _sinyal_isleyici)

    print("[paket-dinleyici] Black Barrier scapy paket dinleyici başlatılıyor", flush=True)
    print(f"[paket-dinleyici] DB:        {db.DB_YOLU}", flush=True)
    print(f"[paket-dinleyici] Arayüz(ler): {', '.join(ARAYUZLER)}", flush=True)
    print(f"[paket-dinleyici] BPF filter: {BPF_FILTRESI}", flush=True)

    if DEVRE_DISI:
        print("[paket-dinleyici] BB_PAKET_DEVRE_DISI=1 → sniff başlatılmıyor (dev modu).", flush=True)
        while _CALISIYOR:
            time.sleep(1)
        return 0

    # DB'yi hazırla
    try:
        db.veritabanini_baslat()
    except Exception as e:
        print(f"[paket-dinleyici] DB başlatma hatası: {e}", flush=True)
        return 1

    # Engelleme kurallarını ilk kez yükle (yakalama başlamadan hazır olsun)
    blok_kurallarini_yenile()
    with _BLOK_KILIT:
        _blok_sayisi = len(_BLOK_KURALLAR)
    print(f"[paket-dinleyici] {_blok_sayisi} aktif engelleme kuralı yüklendi "
          f"(her {BLOK_YENILEME_SN:.0f}sn yenilenir)", flush=True)

    # DB writer thread
    writer = threading.Thread(target=db_yazici_dongusu, daemon=False, name='db-writer')
    writer.start()

    # Her interface için ayrı sniff thread
    sniff_thread_listesi = []
    for iface in ARAYUZLER:
        t = threading.Thread(target=sniff_thread, args=(iface,), daemon=True, name=f'sniff-{iface}')
        t.start()
        sniff_thread_listesi.append(t)

    # Main thread sadece bekliyor
    try:
        while _CALISIYOR:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # Writer thread'in son batch'i de yazmasını bekle
    writer.join(timeout=5)
    print("[paket-dinleyici] Çıkış tamamlandı.", flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(ana())
