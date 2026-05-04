#!/usr/bin/env python3
"""
Black Barrier — İlk Kurulum Betiği (kurulum.py)
================================================
Ön yükleme sihirbazından çağrılır. Şunları yapar:
  1. Veritabanını ve şemayı oluşturur
  2. Admin kullanıcısını ekler
  3. Varsayılan güvenlik kurallarını ekler

Kullanım:
    python3 kurulum.py --kullanici admin --sifre GucluSifre123
"""

import argparse
import sys
from pathlib import Path

# ── Proje kök dizinini sys.path'e ekle ─────────────────────────
# kurulum.py "FastAPI/" klasöründe, db_yonetici.py bir üst dizinde.
PROJE_KOK = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJE_KOK))

import db_yonetici as db


VARSAYILAN_KURALLAR = [
    # Önce kritik engelleme kuralları (düşük öncelik sayısı = önce işle)
    {
        "kural_adi": "Loopback İzin Ver",
        "yon": "giris",
        "protokol": "herhangi",
        "kaynak_ip": "127.0.0.1",
        "hedef_ip": None,
        "kaynak_port": None,
        "hedef_port": None,
        "eylem": "izin_ver",
        "oncelik": 10,
        "aciklama": "Yerel loopback trafiği her zaman izin verilir"
    },
    {
        "kural_adi": "Kurulu Bağlantılar",
        "yon": "giris",
        "protokol": "herhangi",
        "kaynak_ip": None,
        "hedef_ip": None,
        "kaynak_port": None,
        "hedef_port": None,
        "eylem": "izin_ver",
        "oncelik": 20,
        "aciklama": "Daha önce kurulu/ilişkili bağlantılara izin ver (stateful)"
    },
    {
        "kural_adi": "SSH Yönetim Erişimi",
        "yon": "giris",
        "protokol": "tcp",
        "kaynak_ip": None,
        "hedef_ip": None,
        "kaynak_port": None,
        "hedef_port": "22",
        "eylem": "izin_ver",
        "oncelik": 50,
        "aciklama": "LAN'dan SSH erişimine izin ver"
    },
    {
        "kural_adi": "Web Paneli",
        "yon": "giris",
        "protokol": "tcp",
        "kaynak_ip": None,
        "hedef_ip": None,
        "kaynak_port": None,
        "hedef_port": "8000",
        "eylem": "izin_ver",
        "oncelik": 60,
        "aciklama": "Black Barrier yönetim paneline LAN erişimi"
    },
    {
        "kural_adi": "Tümünü Engelle (Varsayılan)",
        "yon": "giris",
        "protokol": "herhangi",
        "kaynak_ip": None,
        "hedef_ip": None,
        "kaynak_port": None,
        "hedef_port": None,
        "eylem": "engelle",
        "oncelik": 999,
        "aciklama": "Hiçbir kuralla eşleşmeyen trafiği engelle"
    },
]


def main():
    parser = argparse.ArgumentParser(description="Black Barrier Kurulum")
    parser.add_argument("--kullanici", required=True, help="Admin kullanıcı adı")
    parser.add_argument("--sifre", required=True, help="Admin şifresi")
    parser.add_argument("--varsayilan-kurallar", action="store_true",
                        help="Varsayılan güvenlik kurallarını ekle")
    args = parser.parse_args()

    print("=" * 50)
    print("  Black Barrier — Veritabanı Kurulumu")
    print("=" * 50)

    # 1. Şemayı oluştur
    print("\n[1/3] Veritabanı şeması oluşturuluyor...")
    db.veritabanini_baslat()
    print("      ✓ Şema hazır")

    # 2. Admin kullanıcı oluştur
    print(f"\n[2/3] Admin kullanıcısı oluşturuluyor: '{args.kullanici}'")
    if db.kullanici_var_mi():
        print("      ⚠ Veritabanında zaten kullanıcı var, atlanıyor.")
    else:
        try:
            uid = db.kullanici_olustur(args.kullanici, args.sifre)
            print(f"      ✓ Admin oluşturuldu (ID: {uid})")
        except Exception as e:
            print(f"      ✗ Hata: {e}")
            sys.exit(1)

    # 3. Varsayılan kurallar
    if args.varsayilan_kurallar:
        print("\n[3/3] Varsayılan güvenlik kuralları ekleniyor...")
        for kural in VARSAYILAN_KURALLAR:
            try:
                kid = db.kural_ekle(kural)
                print(f"      ✓ [{kid}] {kural['kural_adi']}")
            except Exception as e:
                print(f"      ✗ '{kural['kural_adi']}' eklenemedi: {e}")
    else:
        print("\n[3/3] Varsayılan kurallar atlandı (--varsayilan-kurallar ile eklenebilir)")

    print("\n" + "=" * 50)
    print("  Kurulum tamamlandı!")
    print("  Paneli başlatmak için:")
    print("  uvicorn main:app --host 0.0.0.0 --port 8000")
    print("=" * 50)


if __name__ == "__main__":
    main()
