"""
Black Barrier — Veritabanı Yöneticisi (db_yonetici.py)
========================================================
Bu modül tüm SQLite işlemlerini kapsar.
FastAPI arka ucundan import edilerek kullanılır.

Bağımlılıklar:
    pip install bcrypt==4.0.1
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import bcrypt

# ── Yapılandırma ──────────────────────────────────────────────
DB_YOLU = Path(__file__).parent / "veritabani" / "blackbarrier.db"
SEMA_YOLU = Path(__file__).parent / "veritabani" / "sema.sql"



# ══════════════════════════════════════════════════════════════
#  BAĞLANTI YÖNETİMİ
# ══════════════════════════════════════════════════════════════

def baglanti_al() -> sqlite3.Connection:
    """Thread-safe SQLite bağlantısı döndürür."""
    baglanti = sqlite3.connect(
        DB_YOLU,
        check_same_thread=False,
        detect_types=sqlite3.PARSE_DECLTYPES
    )
    baglanti.row_factory = sqlite3.Row   # Sonuçları dict gibi kullanmak için
    baglanti.execute("PRAGMA journal_mode = WAL")
    baglanti.execute("PRAGMA foreign_keys = ON")
    return baglanti


def veritabanini_baslat():
    """
    Uygulama ilk kez çalıştığında şemayı oluşturur.
    Uvicorn başlarken çağrılmalıdır (startup event).
    """
    DB_YOLU.parent.mkdir(parents=True, exist_ok=True)
    sema = SEMA_YOLU.read_text(encoding="utf-8")

    with baglanti_al() as baglanti:
        baglanti.executescript(sema)
        baglanti.commit()

    print(f"[DB] Veritabanı hazır: {DB_YOLU}")


# ══════════════════════════════════════════════════════════════
#  KULLANICI İŞLEMLERİ
# ══════════════════════════════════════════════════════════════

def kullanici_olustur(kullanici_adi: str, sifre: str, rol: str = "admin") -> int:
    """
    Yeni yönetici oluşturur. Şifreyi bcrypt ile hashler.
    Döndürür: yeni kullanıcının id'si
    """
    hash_deger = bcrypt.hashpw(sifre.encode(), bcrypt.gensalt()).decode()
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO kullanicilar (kullanici_adi, sifre_hash, rol)
               VALUES (?, ?, ?)""",
            (kullanici_adi, hash_deger, rol)
        )
        bg.commit()
        return imle.lastrowid


def kullanici_dogrula(kullanici_adi: str, sifre: str) -> dict | None:
    """
    Kullanıcı adı + şifre doğrulaması.
    Başarılıysa kullanıcı dict'ini, değilse None döndürür.
    """
    with baglanti_al() as bg:
        satir = bg.execute(
            "SELECT * FROM kullanicilar WHERE kullanici_adi = ?",
            (kullanici_adi,)
        ).fetchone()

    if satir and bcrypt.checkpw(sifre.encode(), satir["sifre_hash"].encode()):
        # Son giriş zamanını güncelle
        with baglanti_al() as bg:
            bg.execute(
                "UPDATE kullanicilar SET son_giris_t = ? WHERE id = ?",
                (datetime.now().isoformat(), satir["id"])
            )
            bg.commit()
        return dict(satir)
    return None


def kullanici_var_mi() -> bool:
    """Veritabanında en az bir kullanıcı var mı kontrol eder."""
    with baglanti_al() as bg:
        sayi = bg.execute("SELECT COUNT(*) FROM kullanicilar").fetchone()[0]
    return sayi > 0


# ══════════════════════════════════════════════════════════════
#  GÜVENLİK KURALLARI
# ══════════════════════════════════════════════════════════════

def kurallari_getir(sadece_aktif: bool = True) -> list[dict]:
  """
  Tüm güvenlik kurallarını öncelik sırasıyla döndürür.
  Servis başlangıcında nftables'a uygulamak için kullanılır.
  """
  sorgu = "SELECT * FROM guvenlik_kurallari"
  if sadece_aktif:
      sorgu += " WHERE aktif = 1"
  sorgu += " ORDER BY oncelik ASC, id ASC"

  with baglanti_al() as bg:
      return [dict(s) for s in bg.execute(sorgu).fetchall()]


def kural_ekle(veri: dict) -> int:
    """
    Yeni güvenlik kuralı ekler.
    veri dict'i şu anahtarları içermelidir:
        kural_adi, yon, protokol, eylem
    Opsiyonel: kaynak_ip, hedef_ip, kaynak_port, hedef_port, oncelik, aciklama
    """
    # Opsiyonel alanlar için varsayılan değerler
    varsayilan = {
        "kaynak_ip": None, "hedef_ip": None,
        "kaynak_port": None, "hedef_port": None,
        "oncelik": 100, "aciklama": None
    }
    tam_veri = {**varsayilan, **veri}

    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO guvenlik_kurallari
               (kural_adi, yon, protokol, kaynak_ip, hedef_ip,
                kaynak_port, hedef_port, eylem, oncelik, aciklama)
               VALUES (:kural_adi, :yon, :protokol, :kaynak_ip, :hedef_ip,
                       :kaynak_port, :hedef_port, :eylem,
                       :oncelik, :aciklama)""",
            tam_veri
        )
        bg.commit()
        return imle.lastrowid


def kural_sil(kural_id: int) -> bool:
    """Kuralı siler. Başarılıysa True döner."""
    with baglanti_al() as bg:
        etkilenen = bg.execute(
            "DELETE FROM guvenlik_kurallari WHERE id = ?", (kural_id,)
        ).rowcount
        bg.commit()
    return etkilenen > 0


def kural_durum_degistir(kural_id: int, aktif: bool) -> bool:
    """Kuralı aktifleştirir veya devre dışı bırakır."""
    with baglanti_al() as bg:
        etkilenen = bg.execute(
            """UPDATE guvenlik_kurallari
               SET aktif = ?, guncelleme_t = ?
               WHERE id = ?""",
            (1 if aktif else 0, datetime.now().isoformat(), kural_id)
        ).rowcount
        bg.commit()
    return etkilenen > 0


# ══════════════════════════════════════════════════════════════
#  YÖNLENDİRME KURALLARI
# ══════════════════════════════════════════════════════════════

def yonlendirme_kurallari_getir(sadece_aktif: bool = True) -> list[dict]:
    sorgu = "SELECT * FROM yonlendirme_kurallari"
    if sadece_aktif:
        sorgu += " WHERE aktif = 1"
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(sorgu).fetchall()]


def yonlendirme_kurali_ekle(veri: dict) -> int:
    """
    Yeni NAT/yönlendirme kuralı ekler.
    veri: kural_adi, tur, protokol, [dis_arayuz, ic_arayuz,
          dis_port, ic_ip, ic_port, aciklama]
    """
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO yonlendirme_kurallari
               (kural_adi, tur, protokol, dis_arayuz, ic_arayuz,
                dis_port, ic_ip, ic_port, aciklama)
               VALUES (:kural_adi, :tur, :protokol, :dis_arayuz, :ic_arayuz,
                       :dis_port, :ic_ip, :ic_port, :aciklama)""",
            veri
        )
        bg.commit()
        return imle.lastrowid


def yonlendirme_kurali_sil(kural_id: int) -> bool:
    with baglanti_al() as bg:
        etkilenen = bg.execute(
            "DELETE FROM yonlendirme_kurallari WHERE id = ?", (kural_id,)
        ).rowcount
        bg.commit()
    return etkilenen > 0


# ══════════════════════════════════════════════════════════════
#  DHCP İŞLEMLERİ
# ══════════════════════════════════════════════════════════════

def dhcp_ayarlarini_getir(arayuz: str) -> dict | None:
    """Belirtilen arayüzün DHCP ayarlarını döndürür."""
    with baglanti_al() as bg:
        satir = bg.execute(
            "SELECT * FROM dhcp_ayarlari WHERE arayuz = ?", (arayuz,)
        ).fetchone()
    return dict(satir) if satir else None


def dhcp_ayarlarini_kaydet(arayuz: str, veri: dict) -> bool:
    """
    DHCP ayarlarını günceller (upsert — yoksa ekler).
    veri: aktif, alt_ag, alt_ag_maskesi, havuz_baslangic,
          havuz_bitis, ag_gecidi, dns_sunuculari, kira_suresi
    """
    tam_veri = {**veri, "arayuz": arayuz, "guncelleme_t": datetime.now().isoformat()}
    with baglanti_al() as bg:
        bg.execute(
            """INSERT INTO dhcp_ayarlari
                   (arayuz, aktif, alt_ag, alt_ag_maskesi,
                    havuz_baslangic, havuz_bitis, ag_gecidi,
                    dns_sunuculari, kira_suresi, guncelleme_t)
               VALUES (:arayuz, :aktif, :alt_ag, :alt_ag_maskesi,
                       :havuz_baslangic, :havuz_bitis, :ag_gecidi,
                       :dns_sunuculari, :kira_suresi, :guncelleme_t)
               ON CONFLICT(arayuz) DO UPDATE SET
                   aktif=excluded.aktif,
                   alt_ag=excluded.alt_ag,
                   alt_ag_maskesi=excluded.alt_ag_maskesi,
                   havuz_baslangic=excluded.havuz_baslangic,
                   havuz_bitis=excluded.havuz_bitis,
                   ag_gecidi=excluded.ag_gecidi,
                   dns_sunuculari=excluded.dns_sunuculari,
                   kira_suresi=excluded.kira_suresi,
                   guncelleme_t=excluded.guncelleme_t""",
            tam_veri
        )
        bg.commit()
    return True


def dhcp_kiralamalari_getir(arayuz: str | None = None) -> list[dict]:
    """Aktif DHCP kiralamalarını döndürür."""
    sorgu = "SELECT * FROM dhcp_kiralamalari WHERE durum = 'aktif'"
    parametreler = []
    if arayuz:
        sorgu += " AND arayuz = ?"
        parametreler.append(arayuz)
    sorgu += " ORDER BY kira_baslangic DESC"

    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(sorgu, parametreler).fetchall()]


def dhcp_kiralamasi_ekle_veya_guncelle(veri: dict) -> int:
    """
    MAC adresi zaten varsa günceller, yoksa yeni kiralama ekler.
    veri: arayuz, ip_adresi, mac_adresi, host_adi, kira_bitis
    """
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO dhcp_kiralamalari
               (arayuz, ip_adresi, mac_adresi, host_adi, kira_bitis)
               VALUES (:arayuz, :ip_adresi, :mac_adresi, :host_adi, :kira_bitis)
               ON CONFLICT(mac_adresi, arayuz) DO UPDATE SET
                   ip_adresi   = excluded.ip_adresi,
                   host_adi    = excluded.host_adi,
                   kira_bitis  = excluded.kira_bitis,
                   kira_baslangic = datetime('now'),
                   durum       = 'aktif'""",
            veri
        )
        bg.commit()
        return imle.lastrowid


def suresi_dolan_kiralamalari_temizle() -> int:
    """Süresi dolmuş kiralamaları 'suresi_dolmus' olarak işaretler."""
    with baglanti_al() as bg:
        etkilenen = bg.execute(
            """UPDATE dhcp_kiralamalari
               SET durum = 'suresi_dolmus'
               WHERE kira_bitis < datetime('now') AND durum = 'aktif'"""
        ).rowcount
        bg.commit()
    return etkilenen


# ══════════════════════════════════════════════════════════════
#  TRAFİK KAYITLARI
# ══════════════════════════════════════════════════════════════

def trafik_kaydi_ekle(veri: dict) -> int:
    """
    Yeni trafik log kaydı ekler.
    veri: eylem, protokol, kaynak_ip, kaynak_port,
          hedef_ip, hedef_port, [kural_id, arayuz, paket_boyutu, aciklama]
    """
    # Opsiyonel alanlar için varsayılan değerler
    varsayilan = {
        "kural_id": None, "arayuz": None,
        "paket_boyutu": None, "aciklama": None
    }
    tam_veri = {**varsayilan, **veri}

    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO trafik_kayitlari
               (kural_id, eylem, protokol, kaynak_ip, kaynak_port,
                hedef_ip, hedef_port, arayuz, paket_boyutu, aciklama)
               VALUES (:kural_id, :eylem, :protokol, :kaynak_ip, :kaynak_port,
                       :hedef_ip, :hedef_port, :arayuz, :paket_boyutu, :aciklama)""",
            tam_veri
        )
        bg.commit()
        return imle.lastrowid


def trafik_kayitlarini_getir(
    limit: int = 100,
    eylem_filtresi: str | None = None,
    kaynak_ip_filtresi: str | None = None
) -> list[dict]:
    """
    Trafik kayıtlarını en yeniden eskiye sıralar.
    Filtreler opsiyoneldir.
    """
    kosullar = []
    parametreler = []

    if eylem_filtresi:
        kosullar.append("eylem = ?")
        parametreler.append(eylem_filtresi)
    if kaynak_ip_filtresi:
        kosullar.append("kaynak_ip LIKE ?")
        parametreler.append(f"%{kaynak_ip_filtresi}%")

    sorgu = "SELECT * FROM trafik_kayitlari"
    if kosullar:
        sorgu += " WHERE " + " AND ".join(kosullar)
    sorgu += " ORDER BY zaman DESC LIMIT ?"
    parametreler.append(limit)

    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(sorgu, parametreler).fetchall()]


def trafik_istatistiklerini_getir() -> dict:
    """Kontrol paneli için özet istatistikler döndürür."""
    with baglanti_al() as bg:
        toplam = bg.execute("SELECT COUNT(*) FROM trafik_kayitlari").fetchone()[0]
        engellenen = bg.execute(
            "SELECT COUNT(*) FROM trafik_kayitlari WHERE eylem = 'engelle'"
        ).fetchone()[0]
        son_1_saat = bg.execute(
            """SELECT COUNT(*) FROM trafik_kayitlari
               WHERE zaman >= datetime('now', '-1 hour')"""
        ).fetchone()[0]

    return {
        "toplam_kayit": toplam,
        "engellenen_baglanti": engellenen,
        "son_1_saat_aktivite": son_1_saat,
        "aktif_kural_sayisi": len(kurallari_getir(sadece_aktif=True))
    }
