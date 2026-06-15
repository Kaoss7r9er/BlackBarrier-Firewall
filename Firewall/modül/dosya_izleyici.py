"""
Black Barrier — Dosya Bütünlüğü İzleyici (File Integrity Monitor)
=================================================================
Proje dizinindeki kod/yapı dosyalarını sha256 ile özetler, her tarama
sonunda DB'deki baseline ile karşılaştırır ve değişen/yeni/silinen
dosyaları `dosya_degisiklikleri` tablosuna yazar.

Panel: Sistem Logları sekmesinde "Dosya Değişiklikleri" kartı bu kayıtları
gösterir ("şu tarihte bu dosyada değişiklik oldu").

Tarama lazy çalışır: ilgili endpoint çağrıldığında veya servis startup'ında
yapılır. Sık çağrılmasını engellemek için 5 saniyelik bir throttle vardır.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Any

import db_yonetici as db


# ── Yapılandırma ──────────────────────────────────────────────
PROJE_KOK = Path(__file__).resolve().parent.parent   # /opt/blackbarrier/Firewall (VM'de)
DAHIL_UZANTILAR = {".py", ".js", ".html", ".css", ".sql", ".sh", ".md", ".ps1", ".bat"}
HARIC_KLASORLER = {".venv", "__pycache__", ".git", "veritabani", "arsiv",
                   "node_modules", ".idea", ".vscode"}
MAX_DOSYA_BOYUTU = 5 * 1024 * 1024   # 5 MB üzeri dosyalar atlanır (PDF gibi ağırlar)

_THROTTLE_SN = 5.0
_son_tarama_t: float = 0.0


# ── Yardımcılar ───────────────────────────────────────────────
def _sha256(yol: Path) -> str:
    """Dosyanın sha256 hex özetini hesaplar."""
    h = hashlib.sha256()
    with yol.open("rb") as f:
        for parca in iter(lambda: f.read(65536), b""):
            h.update(parca)
    return h.hexdigest()


def _izlenecek_dosyalari_topla() -> list[tuple[str, Path]]:
    """PROJE_KOK altında izlenecek (rel_yol, abs_yol) listesini döndürür."""
    sonuc: list[tuple[str, Path]] = []
    for kok, klasorler, dosyalar in os.walk(PROJE_KOK):
        # Hariç klasörleri walk'tan düşür (in-place)
        klasorler[:] = [k for k in klasorler if k not in HARIC_KLASORLER and not k.startswith(".")]
        for ad in dosyalar:
            uz = Path(ad).suffix.lower()
            if uz not in DAHIL_UZANTILAR:
                continue
            tam = Path(kok) / ad
            try:
                if tam.stat().st_size > MAX_DOSYA_BOYUTU:
                    continue
            except OSError:
                continue
            try:
                rel = tam.relative_to(PROJE_KOK)
            except ValueError:
                continue
            # Tutarlı ayraç için POSIX biçimi (Windows + Linux'ta aynı kayıt)
            sonuc.append((rel.as_posix(), tam))
    return sonuc


# ── Tarama ────────────────────────────────────────────────────
def tarama_yap(zorla: bool = False) -> dict[str, Any]:
    """
    İzlenen dosyaları sha256 ile özetler ve baseline ile karşılaştırır.

    İlk kez (baseline boş) çalıştırılırsa SESSİZ baseline doldurur (değişim
    logu yazılmaz; bu doğal "bilinen iyi durum"dur). Sonraki çağrılarda
    yeni/değişen/silinen dosyalar `dosya_degisiklikleri` tablosuna yazılır.

    `zorla=False` ise 5 saniye içinde tekrar çağrılırsa cache yanıt verir.
    Döndürür: {"yeni": n, "degisti": n, "silindi": n, "tarama_atlandi": bool}
    """
    global _son_tarama_t
    simdi = time.monotonic()
    if not zorla and (simdi - _son_tarama_t) < _THROTTLE_SN:
        return {"yeni": 0, "degisti": 0, "silindi": 0, "tarama_atlandi": True}
    _son_tarama_t = simdi

    sessiz = db.dosya_izleme_bos_mu()   # baseline boşsa ilk dolduruşta log basma

    baseline = db.dosya_izleme_tum()
    mevcut_yollar: set[str] = set()
    yeni = degisti = silindi = 0

    for rel_yol, tam_yol in _izlenecek_dosyalari_topla():
        mevcut_yollar.add(rel_yol)
        try:
            ozet = _sha256(tam_yol)
            boyut = tam_yol.stat().st_size
        except OSError:
            continue

        eski = baseline.get(rel_yol)
        if eski is None:
            # Yeni dosya
            if not sessiz:
                db.dosya_degisikligi_ekle(rel_yol, "yeni", None, ozet, boyut)
                yeni += 1
            db.dosya_izleme_kaydet(rel_yol, ozet, boyut)
        elif eski["ozet"] != ozet:
            # Değişmiş
            if not sessiz:
                db.dosya_degisikligi_ekle(rel_yol, "degisti", eski["ozet"], ozet, boyut)
                degisti += 1
            db.dosya_izleme_kaydet(rel_yol, ozet, boyut)
        # eşit → atla

    # Silinen dosyalar: baseline'da olup mevcut taramada görünmeyenler
    for eski_yol, eski_kayit in baseline.items():
        if eski_yol in mevcut_yollar:
            continue
        if not sessiz:
            db.dosya_degisikligi_ekle(eski_yol, "silindi", eski_kayit["ozet"], None, None)
            silindi += 1
        db.dosya_izleme_sil(eski_yol)

    return {"yeni": yeni, "degisti": degisti, "silindi": silindi, "tarama_atlandi": False}
