"""
Black Barrier — Trafik Arşivleyici
==================================
Trafik kayıtlarını periyodik olarak (12 saatte bir) JSON snapshot'ı + sha256
damgası ile diske yazar ve `trafik_arsivi` tablosuna kaydeder.

Amaç:
    • Olay sonrası kanıt koruma (forensic evidence preservation)
    • Bütünlük doğrulama (sha256 ile dosyanın değişip değişmediği kontrol edilebilir)
    • Uzun süreli saklama (DB rotasyonu durumunda da snapshot kalır)

Çalışma mantığı:
    • Her snapshot, bir önceki snapshot'ın `son_kayit_id`'sinden BÜYÜK trafik
      kayıtlarını içerir → snapshot'lar üst üste binmez, boşluk bırakmaz.
    • İlk çalıştırmada (hiç snapshot yoksa) o anki TÜM trafik_kayitlari içerilir.
    • Yeni kayıt yoksa snapshot oluşturulmaz (gürültü olmaz).
    • Snapshot diske JSON olarak yazılır (kanonik: sıralı anahtar, sıkı virgül).
      Yanına `<dosya>.sha256` sidecar yazılır (linux `sha256sum -c` ile doğrulanabilir).
    • Background task: servisle birlikte başlar, 12 saatlik döngüde çalışır.
      Restart sonrası "son arşivden bu yana geçen süreyi" hesaplayıp gerekirse
      hemen tekrar arşivler — yani 11. saatte panel restart olsa bile veriler kaybolmaz.

Manuel tetikleme: POST /api/trafik/arsiv/calistir endpoint'i (admin).
"""

import asyncio
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any

import db_yonetici as db


# ── Yapılandırma ──────────────────────────────────────────────
PROJE_KOK = Path(__file__).resolve().parent.parent           # /opt/blackbarrier/Firewall
ARSIV_KOK = PROJE_KOK / "arsiv" / "trafik"                   # snapshot'lar burada
ARSIV_ARALIGI_SN = 12 * 3600                                  # 12 saat
HATA_BEKLEME_SN = 60                                          # exception sonrası bu kadar bekle
MAX_KAYIT_PER_SNAPSHOT = 1_000_000                            # tek snapshot için üst limit

# Eşzamanlı çağrılarda (background loop + manuel POST) snapshot çakışmasın
_KILIT = Lock()


def _kanonik_json(veri: Any) -> bytes:
    """sha256'nın aynı içerikte aynı çıkması için kanonik (deterministik) JSON üret."""
    return json.dumps(
        veri,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _zaman_etiketi() -> str:
    """Dosya adında kullanılacak güvenli zaman damgası: 2026-05-30_120000."""
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")


def bir_kez_calistir() -> dict[str, Any]:
    """
    Senkron snapshot işlemi. Background task ve manuel POST aynı fonksiyonu çağırır.

    Döndürür:
        {
            "yapildi": bool,             # True = snapshot oluşturuldu
            "neden": str | None,         # yapildi=False ise nedeni
            "arsiv_id": int | None,
            "dosya_yolu": str | None,    # PROJE_KOK'a göre göreceli
            "sha256": str | None,
            "kayit_sayisi": int,
            "boyut_byte": int,
        }
    """
    bos_sonuc = {
        "yapildi": False, "neden": None, "arsiv_id": None,
        "dosya_yolu": None, "sha256": None,
        "kayit_sayisi": 0, "boyut_byte": 0,
    }

    if not _KILIT.acquire(blocking=False):
        bos_sonuc["neden"] = "Zaten bir arşivleme çalışıyor"
        return bos_sonuc

    try:
        son_id = db.trafik_arsivi_son_kayit_id()   # 0 = hiç arşiv yok
        kayitlar = db.trafik_kayitlari_aralik_getir(son_id, limit=MAX_KAYIT_PER_SNAPSHOT)

        if not kayitlar:
            bos_sonuc["neden"] = "Yeni trafik kaydı yok — snapshot atlandı"
            return bos_sonuc

        ARSIV_KOK.mkdir(parents=True, exist_ok=True)
        zaman = _zaman_etiketi()
        ilk_kayit_id = int(kayitlar[0]["id"])
        son_kayit_id = int(kayitlar[-1]["id"])

        # Snapshot içeriği: meta + kayıtlar. Meta'da snapshot'un kendi tanımı.
        snapshot = {
            "meta": {
                "olusturma_t": datetime.now().isoformat(timespec="seconds"),
                "kayit_sayisi": len(kayitlar),
                "ilk_kayit_id": ilk_kayit_id,
                "son_kayit_id": son_kayit_id,
                "kaynak": "blackbarrier.trafik_kayitlari",
                "surum": 1,
            },
            "kayitlar": kayitlar,
        }
        govde = _kanonik_json(snapshot)
        ozet = hashlib.sha256(govde).hexdigest()

        dosya_adi = f"trafik-{zaman}.json"
        tam_yol = ARSIV_KOK / dosya_adi
        tam_yol.write_bytes(govde)

        # Sidecar sha256: linux `sha256sum -c` ile doğrulanabilir biçim
        (ARSIV_KOK / f"{dosya_adi}.sha256").write_text(
            f"{ozet}  {dosya_adi}\n", encoding="utf-8"
        )

        rel_yol = tam_yol.relative_to(PROJE_KOK).as_posix()
        boyut = len(govde)
        arsiv_id = db.trafik_arsivi_kaydet(
            dosya_yolu=rel_yol,
            sha256=ozet,
            kayit_sayisi=len(kayitlar),
            ilk_kayit_id=ilk_kayit_id,
            son_kayit_id=son_kayit_id,
            boyut_byte=boyut,
        )

        print(f"[arşiv] snapshot oluşturuldu: {rel_yol} "
              f"({len(kayitlar)} kayıt, {boyut} B, sha256={ozet[:16]}…)",
              flush=True)

        return {
            "yapildi": True, "neden": None, "arsiv_id": arsiv_id,
            "dosya_yolu": rel_yol, "sha256": ozet,
            "kayit_sayisi": len(kayitlar), "boyut_byte": boyut,
        }
    except Exception as e:
        print(f"[arşiv] HATA: {e}", file=sys.stderr, flush=True)
        bos_sonuc["neden"] = f"hata: {e}"
        return bos_sonuc
    finally:
        _KILIT.release()


def _gecen_saniye(iso_zaman: str) -> float:
    """ISO zaman string'inden şimdiye kadar geçen saniyeyi döndürür."""
    try:
        # DB datetime('now') TEXT olarak "YYYY-MM-DD HH:MM:SS" döndürür → fromisoformat boşlukla da kabul eder (Py 3.11+).
        t = datetime.fromisoformat(iso_zaman.replace(" ", "T"))
        return max(0.0, (datetime.now() - t).total_seconds())
    except Exception:
        return ARSIV_ARALIGI_SN   # parse edemezsek "zaten zamanı gelmiş" varsay


async def arka_plan_dongusu() -> None:
    """
    Background task. Servis başlarken oluşturulur, kapanırken iptal edilir.

    Restart-dirençli zamanlama:
        • Hiç arşiv yok                          → hemen ilk arşivi al
        • Son arşivden >= 12 saat geçmiş         → hemen al
        • Daha az geçmiş                         → kalan süreyi bekle, sonra al
    Sonra her 12 saatte bir tekrar.
    """
    print("[arşiv] background task başladı — 12 saatlik döngü", flush=True)
    while True:
        try:
            son_t = db.trafik_arsivi_son_zaman()
            if son_t is None:
                bekle = 0.0
            else:
                bekle = max(0.0, ARSIV_ARALIGI_SN - _gecen_saniye(son_t))
            if bekle > 0:
                await asyncio.sleep(bekle)
            bir_kez_calistir()
            # Bir snapshot aldıktan sonra tam 12 saat bekle
            await asyncio.sleep(ARSIV_ARALIGI_SN)
        except asyncio.CancelledError:
            print("[arşiv] background task iptal edildi", flush=True)
            raise
        except Exception as e:
            print(f"[arşiv] döngü hatası: {e}", file=sys.stderr, flush=True)
            await asyncio.sleep(HATA_BEKLEME_SN)
