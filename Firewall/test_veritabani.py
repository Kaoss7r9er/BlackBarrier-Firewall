#!/usr/bin/env python3
"""
Black Barrier — Veritabanı Doğrulama Test Scripti
Tüm db_yonetici.py fonksiyonlarını test eder.
"""

import sys
import os
import tempfile
from pathlib import Path

# Proje kök dizinini ekle
PROJE_KOK = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJE_KOK))

# Test için geçici veritabanı kullan
import db_yonetici as db

# Orijinal DB yolunu geçici dizine yönlendir
GECICI_DIZIN = PROJE_KOK / "veritabani" / "test_temp"
GECICI_DIZIN.mkdir(parents=True, exist_ok=True)
db.DB_YOLU = GECICI_DIZIN / "test_blackbarrier.db"

BASARILI = 0
BASARISIZ = 0

def test(ad: str, fonksiyon):
    global BASARILI, BASARISIZ
    try:
        fonksiyon()
        print(f"  ✓ {ad}")
        BASARILI += 1
    except Exception as e:
        print(f"  ✗ {ad} — {e}")
        BASARISIZ += 1


def test_veritabani_baslat():
    db.veritabanini_baslat()
    assert db.DB_YOLU.exists(), "Veritabanı dosyası oluşturulmadı"


def test_kullanici_olustur():
    uid = db.kullanici_olustur("test_admin", "Test123!")
    assert uid is not None and uid > 0, f"Geçersiz kullanıcı ID: {uid}"


def test_kullanici_var_mi():
    sonuc = db.kullanici_var_mi()
    assert sonuc == True, "Kullanıcı var olmalıydı"


def test_kullanici_dogrula_basarili():
    sonuc = db.kullanici_dogrula("test_admin", "Test123!")
    assert sonuc is not None, "Doğrulama başarısız olmamalıydı"
    assert sonuc["kullanici_adi"] == "test_admin"


def test_kullanici_dogrula_basarisiz():
    sonuc = db.kullanici_dogrula("test_admin", "yanlis_sifre")
    assert sonuc is None, "Yanlış şifreyle doğrulama başarılı olmamalıydı"


def test_kural_ekle_tam():
    kid = db.kural_ekle({
        "kural_adi": "Test Kuralı",
        "yon": "giris",
        "protokol": "tcp",
        "kaynak_ip": "192.168.1.100",
        "hedef_ip": None,
        "kaynak_port": None,
        "hedef_port": "80",
        "eylem": "engelle",
        "oncelik": 50,
        "aciklama": "Test engelleme kuralı"
    })
    assert kid > 0, f"Kural ekleme başarısız: {kid}"


def test_kural_ekle_opsiyonel_alanlar():
    """Opsiyonel alanlar olmadan kural ekleme — düzeltme öncesi KeyError veriyordu"""
    kid = db.kural_ekle({
        "kural_adi": "Minimal Kural",
        "yon": "cikis",
        "protokol": "udp",
        "eylem": "izin_ver"
    })
    assert kid > 0, f"Opsiyonel alansız kural ekleme başarısız: {kid}"


def test_kurallari_getir():
    kurallar = db.kurallari_getir(sadece_aktif=True)
    assert len(kurallar) >= 2, f"En az 2 kural olmalıydı, bulundu: {len(kurallar)}"


def test_kural_durum_degistir():
    sonuc = db.kural_durum_degistir(1, False)
    assert sonuc == True, "Kural devre dışı bırakma başarısız"
    
    kurallar = db.kurallari_getir(sadece_aktif=True)
    aktif_idler = [k["id"] for k in kurallar]
    assert 1 not in aktif_idler, "Devre dışı kural aktif listede olmamalı"


def test_kural_sil():
    sonuc = db.kural_sil(1)
    assert sonuc == True, "Kural silme başarısız"

    sonuc2 = db.kural_sil(9999)
    assert sonuc2 == False, "Olmayan kural silme True döndürmemeli"


def test_yonlendirme_kurali_ekle():
    yid = db.yonlendirme_kurali_ekle({
        "kural_adi": "Port Yönlendirme",
        "tur": "dnat",
        "protokol": "tcp",
        "dis_arayuz": "eth0",
        "ic_arayuz": "eth1",
        "dis_port": "8080",
        "ic_ip": "192.168.1.10",
        "ic_port": "80",
        "aciklama": "HTTP yönlendirme"
    })
    assert yid > 0


def test_yonlendirme_kurallari_getir():
    kurallar = db.yonlendirme_kurallari_getir()
    assert len(kurallar) >= 1


def test_dhcp_ayarlarini_kaydet_upsert():
    """Upsert testi — var olan arayüz güncellenmeli, olmayan eklenmeli"""
    # LAN zaten sema.sql'de ekleniyor, güncelle
    sonuc = db.dhcp_ayarlarini_kaydet("LAN", {
        "aktif": 1,
        "alt_ag": "192.168.1.0",
        "alt_ag_maskesi": "255.255.255.0",
        "havuz_baslangic": "192.168.1.100",
        "havuz_bitis": "192.168.1.200",
        "ag_gecidi": "192.168.1.1",
        "dns_sunuculari": "8.8.8.8,1.1.1.1",
        "kira_suresi": 86400
    })
    assert sonuc == True

    # Yeni arayüz ekle
    sonuc2 = db.dhcp_ayarlarini_kaydet("DMZ", {
        "aktif": 0,
        "alt_ag": "10.0.0.0",
        "alt_ag_maskesi": "255.255.255.0",
        "havuz_baslangic": "10.0.0.100",
        "havuz_bitis": "10.0.0.200",
        "ag_gecidi": "10.0.0.1",
        "dns_sunuculari": "8.8.8.8",
        "kira_suresi": 43200
    })
    assert sonuc2 == True


def test_dhcp_ayarlarini_getir():
    ayarlar = db.dhcp_ayarlarini_getir("LAN")
    assert ayarlar is not None
    assert ayarlar["alt_ag"] == "192.168.1.0"
    assert ayarlar["aktif"] == 1


def test_dhcp_kiralamasi_ekle():
    kid = db.dhcp_kiralamasi_ekle_veya_guncelle({
        "arayuz": "LAN",
        "ip_adresi": "192.168.1.101",
        "mac_adresi": "AA:BB:CC:DD:EE:01",
        "host_adi": "test-pc",
        "kira_bitis": "2026-12-31T23:59:59"
    })
    assert kid > 0


def test_dhcp_kiralamalari_getir():
    kiralamalar = db.dhcp_kiralamalari_getir("LAN")
    assert len(kiralamalar) >= 1


def test_trafik_kaydi_ekle_tam():
    tid = db.trafik_kaydi_ekle({
        "eylem": "engelle",
        "protokol": "tcp",
        "kaynak_ip": "10.0.0.5",
        "kaynak_port": 54321,
        "hedef_ip": "192.168.1.1",
        "hedef_port": 443,
        "kural_id": None,
        "arayuz": "eth0",
        "paket_boyutu": 1500,
        "aciklama": "Test log kaydı"
    })
    assert tid > 0


def test_trafik_kaydi_ekle_opsiyonel():
    """Opsiyonel alanlar olmadan — düzeltme öncesi KeyError veriyordu"""
    tid = db.trafik_kaydi_ekle({
        "eylem": "izin_ver",
        "protokol": "udp",
        "kaynak_ip": "192.168.1.50",
        "kaynak_port": 12345,
        "hedef_ip": "8.8.8.8",
        "hedef_port": 53
    })
    assert tid > 0


def test_trafik_kayitlarini_getir():
    kayitlar = db.trafik_kayitlarini_getir(limit=10)
    assert len(kayitlar) >= 2


def test_trafik_kayitlarini_filtrele():
    kayitlar = db.trafik_kayitlarini_getir(eylem_filtresi="engelle")
    assert len(kayitlar) >= 1
    assert all(k["eylem"] == "engelle" for k in kayitlar)


def test_trafik_istatistikleri():
    istat = db.trafik_istatistiklerini_getir()
    assert "toplam_kayit" in istat
    assert "engellenen_baglanti" in istat
    assert istat["toplam_kayit"] >= 2


# ══════════════════════════════════════════════════════════════
#  TEST ÇALIŞTIRICI
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  Black Barrier — Veritabanı Doğrulama Testleri")
    print("=" * 55)

    print(f"\n  Test DB: {db.DB_YOLU}\n")

    # Veritabanını başlat
    print("─── Başlatma ──────────────────────────────────")
    test("Veritabanı başlatma", test_veritabani_baslat)

    print("\n─── Kullanıcı İşlemleri ────────────────────────")
    test("Kullanıcı oluşturma", test_kullanici_olustur)
    test("Kullanıcı var mı kontrolü", test_kullanici_var_mi)
    test("Başarılı giriş doğrulama", test_kullanici_dogrula_basarili)
    test("Başarısız giriş doğrulama", test_kullanici_dogrula_basarisiz)

    print("\n─── Güvenlik Kuralları ─────────────────────────")
    test("Kural ekleme (tüm alanlar)", test_kural_ekle_tam)
    test("Kural ekleme (opsiyonel alanlar)", test_kural_ekle_opsiyonel_alanlar)
    test("Kuralları getirme", test_kurallari_getir)
    test("Kural durum değiştirme", test_kural_durum_degistir)
    test("Kural silme", test_kural_sil)

    print("\n─── Yönlendirme Kuralları ──────────────────────")
    test("Yönlendirme kuralı ekleme", test_yonlendirme_kurali_ekle)
    test("Yönlendirme kuralları getirme", test_yonlendirme_kurallari_getir)

    print("\n─── DHCP İşlemleri ────────────────────────────")
    test("DHCP ayarları kaydetme (upsert)", test_dhcp_ayarlarini_kaydet_upsert)
    test("DHCP ayarlarını getirme", test_dhcp_ayarlarini_getir)
    test("DHCP kiralama ekleme", test_dhcp_kiralamasi_ekle)
    test("DHCP kiralamalarını getirme", test_dhcp_kiralamalari_getir)

    print("\n─── Trafik Kayıtları ──────────────────────────")
    test("Trafik kaydı ekleme (tam)", test_trafik_kaydi_ekle_tam)
    test("Trafik kaydı ekleme (opsiyonel)", test_trafik_kaydi_ekle_opsiyonel)
    test("Trafik kayıtlarını getirme", test_trafik_kayitlarini_getir)
    test("Trafik kayıtlarını filtreleme", test_trafik_kayitlarini_filtrele)
    test("Trafik istatistikleri", test_trafik_istatistikleri)

    # Temizlik — test veritabanını sil
    try:
        os.remove(db.DB_YOLU)
        GECICI_DIZIN.rmdir()
    except:
        pass

    print(f"\n{'=' * 55}")
    print(f"  SONUÇ: {BASARILI} başarılı, {BASARISIZ} başarısız")
    print(f"{'=' * 55}")

    sys.exit(0 if BASARISIZ == 0 else 1)
