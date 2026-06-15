#!/usr/bin/env python3
"""
Black Barrier — İlk Kurulum Betiği (kurulum.py)
================================================
Ön yükleme sihirbazından çağrılır. Şunları yapar:
  1. Veritabanını ve şemayı oluşturur
  2. Admin kullanıcısını ekler (rol='admin')
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


# BİLİNÇLİ olarak BOŞ. Eskiden burada bir "default-deny input" seti vardı
# (loopback/SSH/panel izin ver + tümünü engelle). İki sorunu vardı:
#  1) "Kurulu Bağlantılar" kuralı stateful (established/related) olmalıydı ama
#     kural şemasında conntrack desteği yok → kriteri boş kalıp ACCEPT-ALL'a
#     dönüşüyordu, bu da "tümünü engelle" kuralını işlevsiz bırakıyordu.
#  2) conntrack olmadan default-deny, firewall'ın KENDİ giden bağlantılarının
#     dönüş trafiğini de düşürür (DNS/apt kırılır).
# Sistem artık blacklist modunda: policy accept + kullanıcının eklediği engeller.
# Yönetim erişimi (SSH/panel/loopback) nftables_yonetici'deki anti-lockout
# korumalarıyla otomatik güvende. Düzgün default-deny istenirse önce conntrack
# (ct state) desteği eklenmeli — o zaman buraya tutarlı bir set konabilir.
VARSAYILAN_KURALLAR: list[dict] = []


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
            uid = db.kullanici_olustur(
                args.kullanici, args.sifre,
                rol="admin",
                ad_soyad="Sistem Yöneticisi"
            )
            print(f"      ✓ Admin oluşturuldu (ID: {uid}, Rol: admin)")
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
