"""
Black Barrier — nftables Log Toplayıcı (log_toplayici.py)
=========================================================
Ayrı bir systemd servisi (blackbarrier-logparser.service) olarak çalışır.
journalctl -k -f çıktısını izler, `bb:<id> ` prefix'li satırları parse
edip trafik_kayitlari tablosuna yazar.

Çalıştırma:
    sudo python3 /opt/blackbarrier/Firewall/modül/log_toplayici.py
ya da:
    sudo systemctl start blackbarrier-logparser

Beklenen kernel log formatı (nftables log prefix kullanılarak üretilir):
    bb:42 IN=enp0s8 OUT= MAC=... SRC=1.2.3.4 DST=192.168.1.1 LEN=60 ...
        PROTO=TCP SPT=12345 DPT=22 ...

Tasarım:
- DB'ye yazarken aynı SQLite veritabanını (WAL mode) kullanır; main API ile
  güvenli şekilde paralel çalışır.
- Kural ID'den eylem (izin_ver/engelle/reddet) mapping'i 30 sn cache'lenir
  ki her satır için DB sorgusu olmasın.
- SIGTERM/SIGINT ile graceful shutdown.
"""

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import FrameType
from typing import Any, Optional

# ── Proje kök dizinini sys.path'e ekle ─────────────────────────
# log_toplayici.py "modül/" klasöründe, db_yonetici.py bir üst dizinde.
PROJE_KOK = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJE_KOK))

import db_yonetici as db  # noqa: E402

# ── Yapılandırma ──────────────────────────────────────────────
CACHE_TTL_SN = 30                # Kural cache yenileme aralığı
JOURNALCTL_KOMUT = ['journalctl', '-k', '-f', '--no-pager', '-o', 'cat']

# ── Regex: bb:<id> öneki ve nft log alanları ───────────────────
# nftables log satırı tek satırdır; alanlar boşlukla ayrılır: KEY=value
_BB_PREFIX = re.compile(r'\bbb:(\d+)\b')

def _alan_oku(satir: str, anahtar: str) -> Optional[str]:
    """nft log satırından KEY=value formatında bir alanı çıkar."""
    m = re.search(rf'\b{anahtar}=(\S*)', satir)
    if not m:
        return None
    deger = m.group(1)
    return deger if deger else None


def _int_oku(satir: str, anahtar: str) -> Optional[int]:
    deger = _alan_oku(satir, anahtar)
    if deger is None:
        return None
    try:
        return int(deger)
    except ValueError:
        return None


# ══════════════════════════════════════════════════════════════
#  KURAL EYLEM CACHE
# ══════════════════════════════════════════════════════════════

_kural_eylem_cache: dict[int, str] = {}
_cache_son_yenileme: float = 0.0


def kural_eylemini_al(kural_id: int) -> str:
    """
    Verilen ID için kuralın eylemini döndürür.
    Cache TTL'i bitmişse DB'den yeniden okur.

    Özel ID:
      - 0: nftables_yonetici'nin "trafik izleme" catch-all kuralı
           (BB_TRAFIK_IZLEME=1 ile aktif). DB'de karşılığı yok; her zaman
           'izin_ver' olarak işlenir çünkü o kural log+accept yapar.

    Bilinmeyen ID için 'engelle' döner (log gelen kurallar genelde engellemedir
    ve trafik_kayitlari.eylem CHECK constraint'i bunu kabul eder).
    """
    # Catch-all izleme kuralı (DB'de yok, sanal)
    if kural_id == 0:
        return 'izin_ver'

    global _cache_son_yenileme, _kural_eylem_cache
    simdi = time.time()
    if simdi - _cache_son_yenileme > CACHE_TTL_SN:
        try:
            kurallar = db.kurallari_getir(sadece_aktif=False)
            _kural_eylem_cache = {
                int(k['id']): str(k.get('eylem') or 'engelle')
                for k in kurallar
                if k.get('id') is not None
            }
            _cache_son_yenileme = simdi
        except Exception as e:
            print(f"[log-toplayici] Kural cache yenilenemedi: {e}", flush=True)
    eylem = _kural_eylem_cache.get(kural_id, 'engelle')
    if eylem not in ('izin_ver', 'engelle', 'reddet'):
        eylem = 'engelle'
    return eylem


# ══════════════════════════════════════════════════════════════
#  SATIR PARSE
# ══════════════════════════════════════════════════════════════

def satiri_parse_et(satir: str) -> Optional[dict[str, Any]]:
    """
    Kernel log satırından trafik_kayitlari için bir kayıt çıkarır.
    Satırda 'bb:<id>' prefix'i yoksa None döner.
    """
    m = _BB_PREFIX.search(satir)
    if not m:
        return None

    try:
        kural_id = int(m.group(1))
    except ValueError:
        return None

    proto_ham = (_alan_oku(satir, 'PROTO') or '').lower()
    if proto_ham in ('tcp', 'udp', 'icmp'):
        protokol = proto_ham
    else:
        protokol = 'herhangi'

    # IN/OUT bir tane dolu olur, diğeri boş. Hangisi varsa onu al.
    arayuz = _alan_oku(satir, 'IN') or _alan_oku(satir, 'OUT')

    eylem = kural_eylemini_al(kural_id)

    # kural_id=0 catch-all izleme kuralı; DB'de gerçek kural değil → FK NULL
    # (guvenlik_kurallari tablosunda id=0 yok, INSERT FK ihlali yapar).
    db_kural_id: int | None = None if kural_id == 0 else kural_id

    return {
        'kural_id': db_kural_id,
        'eylem': eylem,
        'protokol': protokol,
        'kaynak_ip': _alan_oku(satir, 'SRC'),
        'kaynak_port': _int_oku(satir, 'SPT'),
        'hedef_ip': _alan_oku(satir, 'DST'),
        'hedef_port': _int_oku(satir, 'DPT'),
        'arayuz': arayuz,
        'paket_boyutu': _int_oku(satir, 'LEN'),
        'aciklama': 'izleme' if kural_id == 0 else None,
    }


# ══════════════════════════════════════════════════════════════
#  ANA DÖNGÜ
# ══════════════════════════════════════════════════════════════

_calisiyor = True


def _sinyal_isleyici(signum: int, frame: Optional[FrameType]) -> None:
    global _calisiyor
    print(f"[log-toplayici] Sinyal {signum} alındı, kapatılıyor...", flush=True)
    _calisiyor = False


def _journalctl_ac() -> subprocess.Popen[str]:
    """journalctl alt sürecini başlat. Kapanırsa ana döngü yeniden çağırır."""
    return subprocess.Popen(
        JOURNALCTL_KOMUT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered
    )


def ana() -> int:
    signal.signal(signal.SIGTERM, _sinyal_isleyici)
    signal.signal(signal.SIGINT, _sinyal_isleyici)

    print("[log-toplayici] Black Barrier log toplayıcı başlatılıyor...", flush=True)
    print(f"[log-toplayici] DB: {db.DB_YOLU}", flush=True)

    # DB hazır olduğundan emin ol (ilk açılışta tablolar yoksa oluştur)
    try:
        db.veritabanini_baslat()
    except Exception as e:
        print(f"[log-toplayici] DB başlatılamadı: {e}", flush=True)
        return 1

    yeniden_baglanti_gecikme_sn = 1
    while _calisiyor:
        try:
            proc = _journalctl_ac()
        except FileNotFoundError:
            print("[log-toplayici] 'journalctl' bulunamadı. systemd yüklü mü?", flush=True)
            return 1

        if proc.stdout is None:
            print("[log-toplayici] journalctl stdout açılamadı", flush=True)
            return 1

        print("[log-toplayici] Kernel log akışı izleniyor...", flush=True)
        yeniden_baglanti_gecikme_sn = 1  # Başarılı bağlantı → reset

        try:
            for satir in proc.stdout:
                if not _calisiyor:
                    break
                if 'bb:' not in satir:
                    continue
                kayit = satiri_parse_et(satir)
                if kayit is None:
                    continue
                try:
                    db.trafik_kaydi_ekle(kayit)
                except Exception as e:
                    print(f"[log-toplayici] DB yazma hatası: {e}", flush=True)
        except Exception as e:
            print(f"[log-toplayici] Okuma hatası: {e}", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not _calisiyor:
            break

        # journalctl beklenmedik şekilde kapandı → exponential backoff ile yeniden bağlan
        print(f"[log-toplayici] journalctl kapandı. {yeniden_baglanti_gecikme_sn}s sonra yeniden bağlanılacak.", flush=True)
        time.sleep(yeniden_baglanti_gecikme_sn)
        yeniden_baglanti_gecikme_sn = min(yeniden_baglanti_gecikme_sn * 2, 30)

    print("[log-toplayici] Toplayıcı durdu.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(ana())
