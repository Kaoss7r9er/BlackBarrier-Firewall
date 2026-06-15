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
from typing import Any
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

    # Mevcut kullanıcılara ad_soyad sütunu ekle (migration)
    _migrasyon_uygula()

    print(f"[DB] Veritabanı hazır: {DB_YOLU}")


def _migrasyon_uygula():
    """Mevcut veritabanına yeni sütunları ekler (geriye uyumluluk)."""
    with baglanti_al() as bg:
        try:
            bg.execute("ALTER TABLE kullanicilar ADD COLUMN ad_soyad TEXT DEFAULT ''")
            bg.commit()
        except sqlite3.OperationalError:
            pass

        # dhcp_ayarlari'na sistem interface adı sütunu (dnsmasq için)
        try:
            bg.execute("ALTER TABLE dhcp_ayarlari ADD COLUMN interface_adi TEXT")
            bg.commit()
        except sqlite3.OperationalError:
            pass

        # guvenlik_kurallari'na hedef_tip / hedef_domain / zaman_baslangic / zaman_bitis
        for sutun, varsayilan in (
            ("hedef_tip", "'ip'"),
            ("hedef_domain", "NULL"),
            ("zaman_baslangic", "NULL"),
            ("zaman_bitis", "NULL"),
        ):
            try:
                bg.execute(
                    f"ALTER TABLE guvenlik_kurallari ADD COLUMN {sutun} TEXT DEFAULT {varsayilan}"
                )
                bg.commit()
            except sqlite3.OperationalError:
                pass

        # trafik_kayitlari'na TCP bayrakları (TEXT), TTL (INTEGER) ve
        # info (TEXT — IP'ye karşılık gelen domain, DNS snooping ile) ekle
        for sutun, sql_tip in (
            ("tcp_bayraklari", "TEXT"),
            ("ttl", "INTEGER"),
            ("info", "TEXT"),
        ):
            try:
                bg.execute(f"ALTER TABLE trafik_kayitlari ADD COLUMN {sutun} {sql_tip}")
                bg.commit()
            except sqlite3.OperationalError:
                pass

    # guvenlik_kurallari.yon CHECK'ine 'her' (tüm zincirler) ekle.
    # CHECK değiştirilemez → tablo yeniden kurulur. Reinstall'da DB zaten sıfırdan
    # doğru şemayla gelir; bu yalnızca dosya-güncellemesi (DB silinmeden) senaryosu için.
    _yon_check_migrasyonu()


def _yon_check_migrasyonu() -> None:
    """
    guvenlik_kurallari tablosunun yon CHECK'i 'her' içermiyorsa tabloyu güvenli
    şekilde yeniden kurar (SQLite tablo-yeniden-kurma prosedürü). Idempotent;
    'her' zaten destekleniyorsa hiçbir şey yapmaz.
    """
    # PRAGMA foreign_keys ve DDL'lerin temiz çalışması için autocommit bağlantı
    bg = sqlite3.connect(DB_YOLU, check_same_thread=False)
    try:
        bg.isolation_level = None  # autocommit — açık transaction olmasın
        satir = bg.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='guvenlik_kurallari'"
        ).fetchone()
        if not satir or not satir[0] or "'her'" in satir[0]:
            return  # tablo yok ya da zaten güncel

        # Mevcut sütunları isimle al (eski/yeni sütun sırası farklı olabilir)
        sutunlar = [r[1] for r in bg.execute("PRAGMA table_info(guvenlik_kurallari)").fetchall()]
        ortak = ", ".join(sutunlar)

        bg.execute("PRAGMA foreign_keys = OFF")
        bg.execute("DROP TABLE IF EXISTS _gk_eski")  # önceki yarım kalan denemeden artık
        bg.execute("ALTER TABLE guvenlik_kurallari RENAME TO _gk_eski")
        bg.execute("""
            CREATE TABLE guvenlik_kurallari (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                kural_adi     TEXT    NOT NULL,
                yon           TEXT    NOT NULL CHECK(yon IN ('giris','cikis','ilet','her')),
                protokol      TEXT    NOT NULL CHECK(protokol IN ('tcp','udp','icmp','herhangi')),
                kaynak_ip     TEXT,
                hedef_ip      TEXT,
                hedef_tip     TEXT    DEFAULT 'ip' CHECK(hedef_tip IN ('ip','domain')),
                hedef_domain  TEXT,
                kaynak_port   TEXT,
                hedef_port    TEXT,
                eylem         TEXT    NOT NULL CHECK(eylem IN ('izin_ver','engelle','reddet')),
                oncelik       INTEGER NOT NULL DEFAULT 100,
                aktif         INTEGER NOT NULL DEFAULT 1,
                zaman_baslangic TEXT,
                zaman_bitis   TEXT,
                aciklama      TEXT,
                olusturma_t   TEXT    NOT NULL DEFAULT (datetime('now')),
                guncelleme_t  TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        bg.execute(f"INSERT INTO guvenlik_kurallari ({ortak}) SELECT {ortak} FROM _gk_eski")
        bg.execute("DROP TABLE _gk_eski")
        bg.execute(
            "CREATE INDEX IF NOT EXISTS idx_kural_oncelik ON guvenlik_kurallari (aktif, oncelik)"
        )
        bg.execute("PRAGMA foreign_keys = ON")
        print("[DB] guvenlik_kurallari yon CHECK migrasyonu: 'her' eklendi")
    except sqlite3.Error as e:
        print(f"[DB] yon CHECK migrasyonu atlandı: {e}")
    finally:
        bg.close()


# ══════════════════════════════════════════════════════════════
#  KULLANICI İŞLEMLERİ
# ══════════════════════════════════════════════════════════════

GECERLI_ROLLER = ("admin", "yonetici", "izleyici")


def kullanici_olustur(kullanici_adi: str, sifre: str,
                      rol: str = "yonetici", ad_soyad: str = "") -> int:
    """
    Yeni kullanıcı oluşturur. Şifreyi bcrypt ile hashler.
    Döndürür: yeni kullanıcının id'si
    """
    if rol not in GECERLI_ROLLER:
        raise ValueError(f"Geçersiz rol: {rol}. Geçerli roller: {GECERLI_ROLLER}")
    hash_deger = bcrypt.hashpw(sifre.encode(), bcrypt.gensalt()).decode()
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO kullanicilar (kullanici_adi, sifre_hash, rol, ad_soyad)
               VALUES (?, ?, ?, ?)""",
            (kullanici_adi, hash_deger, rol, ad_soyad)
        )
        bg.commit()
        return imle.lastrowid


def kullanici_dogrula(kullanici_adi: str, sifre: str) -> dict[str, Any] | None:
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


def kullanicilari_getir() -> list[dict[str, Any]]:
    """Tüm kullanıcıları listeler."""
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(
            """SELECT id, kullanici_adi, ad_soyad, rol,
                      olusturma_t, son_giris_t
               FROM kullanicilar
               ORDER BY id ASC"""
        ).fetchall()]

def kullanici_guncelle(kullanici_id: int, ad_soyad: str,
                       rol: str | None = None, sifre: str | None = None) -> bool:
    """Mevcut bir kullanıcıyı günceller. rol/sifre opsiyoneldir."""
    if rol is not None and rol not in GECERLI_ROLLER:
        raise ValueError(f"Geçersiz rol: {rol}. Geçerli roller: {GECERLI_ROLLER}")

    alanlar = ["ad_soyad = ?"]
    degerler = [ad_soyad]
    if rol is not None:
        alanlar.append("rol = ?")
        degerler.append(rol)
    if sifre:
        sifre_hash = bcrypt.hashpw(sifre.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        alanlar.append("sifre_hash = ?")
        degerler.append(sifre_hash)
    degerler.append(kullanici_id)

    with baglanti_al() as bg:
        etkilenen = bg.execute(
            f"UPDATE kullanicilar SET {', '.join(alanlar)} WHERE id = ?",
            degerler
        ).rowcount
        bg.commit()
    return etkilenen > 0


def kullanici_bilgisi_getir(kullanici_adi: str) -> dict[str, Any] | None:
    """Tek bir kullanıcının detaylı bilgilerini döndürür."""
    with baglanti_al() as bg:
        satir = bg.execute(
            """SELECT id, kullanici_adi, ad_soyad, rol,
                      olusturma_t, son_giris_t
               FROM kullanicilar
               WHERE kullanici_adi = ?""",
            (kullanici_adi,)
        ).fetchone()
    return dict(satir) if satir else None


def kullanici_sil(kullanici_id: int) -> bool:
    """Kullanıcıyı siler. Başarılıysa True döner."""
    with baglanti_al() as bg:
        etkilenen = bg.execute(
            "DELETE FROM kullanicilar WHERE id = ?", (kullanici_id,)
        ).rowcount
        bg.commit()
    return etkilenen > 0


# ══════════════════════════════════════════════════════════════
#  GİRİŞ KAYITLARI
# ══════════════════════════════════════════════════════════════

def giris_kaydi_ekle(kullanici_id: int | None, kullanici_adi: str,
                     ip_adresi: str = "", user_agent: str = "",
                     basarili: bool = True) -> int:
    """Giriş denemesini loglar."""
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO giris_kayitlari
               (kullanici_id, kullanici_adi, ip_adresi, user_agent, basarili)
               VALUES (?, ?, ?, ?, ?)""",
            (kullanici_id, kullanici_adi, ip_adresi, user_agent,
             1 if basarili else 0)
        )
        bg.commit()
        return imle.lastrowid


def giris_kayitlari_getir(kullanici_id: int | None = None,
                          limit: int = 50) -> list[dict[str, Any]]:
    """Giriş kayıtlarını döndürür. kullanici_id verilirse filtreler."""
    sorgu = "SELECT * FROM giris_kayitlari"
    parametreler = []
    if kullanici_id:
        sorgu += " WHERE kullanici_id = ?"
        parametreler.append(kullanici_id)
    sorgu += " ORDER BY zaman DESC LIMIT ?"
    parametreler.append(limit)

    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(sorgu, parametreler).fetchall()]


# ══════════════════════════════════════════════════════════════
#  SİSTEM TERCİHLERİ
# ══════════════════════════════════════════════════════════════

def sistem_tercihi_kaydet(kullanici_id: int, anahtar: str, deger: str) -> bool:
    """Kullanıcı tercihini kaydeder (upsert)."""
    with baglanti_al() as bg:
        bg.execute(
            """INSERT INTO sistem_tercihleri (kullanici_id, anahtar, deger, guncelleme_t)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(kullanici_id, anahtar) DO UPDATE SET
                   deger=excluded.deger, guncelleme_t=excluded.guncelleme_t""",
            (kullanici_id, anahtar, deger, datetime.now().isoformat())
        )
        bg.commit()
    return True


def sistem_tercihleri_getir(kullanici_id: int) -> dict[str, Any]:
    """Kullanıcının tüm tercihlerini {anahtar: deger} olarak döndürür."""
    with baglanti_al() as bg:
        satirlar = bg.execute(
            "SELECT anahtar, deger FROM sistem_tercihleri WHERE kullanici_id = ?",
            (kullanici_id,)
        ).fetchall()
    return {s["anahtar"]: s["deger"] for s in satirlar}


# ══════════════════════════════════════════════════════════════
#  GÜVENLİK KURALLARI
# ══════════════════════════════════════════════════════════════

def kurallari_getir(sadece_aktif: bool = True) -> list[dict[str, Any]]:
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


def engelli_domainleri_getir() -> list[str]:
    """
    Aktif engelleme kurallarından domain hedeflerini döndürür (DNS blocklist için).
    Yalnızca hedef_tip='domain' ve eylem engelle/reddet olan aktif kurallar.
    nftables IP üzerinden çalışır; youtube gibi çok-IP'li adresler ancak DNS
    seviyesinde (dnsmasq address=/domain/0.0.0.0) güvenilir engellenebilir.
    """
    with baglanti_al() as bg:
        satirlar = bg.execute(
            """SELECT DISTINCT hedef_domain FROM guvenlik_kurallari
               WHERE aktif = 1
                 AND hedef_tip = 'domain'
                 AND eylem IN ('engelle', 'reddet')
                 AND hedef_domain IS NOT NULL
                 AND hedef_domain != ''"""
        ).fetchall()
    return [s[0] for s in satirlar]


def kural_ekle(veri: dict[str, Any]) -> int:
    """
    Yeni güvenlik kuralı ekler.
    veri dict'i şu anahtarları içermelidir:
        kural_adi, yon, protokol, eylem
    Opsiyonel: kaynak_ip, hedef_ip, kaynak_port, hedef_port, oncelik, aciklama,
               aktif, hedef_tip, hedef_domain, zaman_baslangic, zaman_bitis
    """
    varsayilan = {
        "kaynak_ip": None, "hedef_ip": None,
        "kaynak_port": None, "hedef_port": None,
        "oncelik": 100, "aciklama": None,
        "aktif": 1,
        "hedef_tip": "ip", "hedef_domain": None,
        "zaman_baslangic": None, "zaman_bitis": None,
    }
    tam_veri = {**varsayilan, **veri}
    # aktif bool ise int'e çevir
    if isinstance(tam_veri["aktif"], bool):
        tam_veri["aktif"] = 1 if tam_veri["aktif"] else 0

    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO guvenlik_kurallari
               (kural_adi, yon, protokol, kaynak_ip, hedef_ip,
                hedef_tip, hedef_domain,
                kaynak_port, hedef_port, eylem, oncelik, aktif,
                zaman_baslangic, zaman_bitis, aciklama)
               VALUES (:kural_adi, :yon, :protokol, :kaynak_ip, :hedef_ip,
                       :hedef_tip, :hedef_domain,
                       :kaynak_port, :hedef_port, :eylem,
                       :oncelik, :aktif,
                       :zaman_baslangic, :zaman_bitis, :aciklama)""",
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

def yonlendirme_kurallari_getir(sadece_aktif: bool = True) -> list[dict[str, Any]]:
    sorgu = "SELECT * FROM yonlendirme_kurallari"
    if sadece_aktif:
        sorgu += " WHERE aktif = 1"
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(sorgu).fetchall()]


def yonlendirme_kurali_ekle(veri: dict[str, Any]) -> int:
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

def dhcp_ayarlarini_getir(arayuz: str) -> dict[str, Any] | None:
    """Belirtilen arayüzün DHCP ayarlarını döndürür."""
    with baglanti_al() as bg:
        satir = bg.execute(
            "SELECT * FROM dhcp_ayarlari WHERE arayuz = ?", (arayuz,)
        ).fetchone()
    return dict(satir) if satir else None


def dhcp_ayarlarini_kaydet(arayuz: str, veri: dict[str, Any]) -> bool:
    """
    DHCP ayarlarını günceller (upsert — yoksa ekler).
    veri: aktif, alt_ag, alt_ag_maskesi, havuz_baslangic, havuz_bitis,
          ag_gecidi, dns_sunuculari, kira_suresi, interface_adi
    """
    tam_veri = {
        "interface_adi": None,
        **veri,
        "arayuz": arayuz,
        "guncelleme_t": datetime.now().isoformat(),
    }
    with baglanti_al() as bg:
        bg.execute(
            """INSERT INTO dhcp_ayarlari
                   (arayuz, interface_adi, aktif, alt_ag, alt_ag_maskesi,
                    havuz_baslangic, havuz_bitis, ag_gecidi,
                    dns_sunuculari, kira_suresi, guncelleme_t)
               VALUES (:arayuz, :interface_adi, :aktif, :alt_ag, :alt_ag_maskesi,
                       :havuz_baslangic, :havuz_bitis, :ag_gecidi,
                       :dns_sunuculari, :kira_suresi, :guncelleme_t)
               ON CONFLICT(arayuz) DO UPDATE SET
                   interface_adi=excluded.interface_adi,
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


def tum_dhcp_ayarlarini_getir() -> list[dict[str, Any]]:
    """dnsmasq config üretimi için tüm DHCP yapılandırmalarını getirir."""
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(
            "SELECT * FROM dhcp_ayarlari ORDER BY id ASC"
        ).fetchall()]


def dhcp_kiralamalari_getir(arayuz: str | None = None) -> list[dict[str, Any]]:
    """Aktif DHCP kiralamalarını döndürür."""
    sorgu = "SELECT * FROM dhcp_kiralamalari WHERE durum = 'aktif'"
    parametreler = []
    if arayuz:
        sorgu += " AND arayuz = ?"
        parametreler.append(arayuz)
    sorgu += " ORDER BY kira_baslangic DESC"

    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(sorgu, parametreler).fetchall()]


def dhcp_kiralamasi_ekle_veya_guncelle(veri: dict[str, Any]) -> int:
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

_TRAFIK_INSERT_SQL = """INSERT INTO trafik_kayitlari
       (kural_id, eylem, protokol, kaynak_ip, kaynak_port,
        hedef_ip, hedef_port, arayuz, paket_boyutu,
        tcp_bayraklari, ttl, aciklama, info)
       VALUES (:kural_id, :eylem, :protokol, :kaynak_ip, :kaynak_port,
               :hedef_ip, :hedef_port, :arayuz, :paket_boyutu,
               :tcp_bayraklari, :ttl, :aciklama, :info)"""

_TRAFIK_VARSAYILAN = {
    "kural_id": None, "arayuz": None, "paket_boyutu": None,
    "tcp_bayraklari": None, "ttl": None, "aciklama": None,
    "info": None,   # IP'ye karşılık gelen domain (DNS snooping) — "site" bilgisi
}


def trafik_kaydi_ekle(veri: dict[str, Any]) -> int:
    """
    Yeni trafik log kaydı ekler.
    veri: eylem, protokol, kaynak_ip, kaynak_port,
          hedef_ip, hedef_port, [kural_id, arayuz, paket_boyutu,
          tcp_bayraklari, ttl, aciklama]
    """
    tam_veri = {**_TRAFIK_VARSAYILAN, **veri}
    with baglanti_al() as bg:
        imle = bg.execute(_TRAFIK_INSERT_SQL, tam_veri)
        bg.commit()
        return imle.lastrowid


def trafik_kayitlarini_batch_ekle(kayitlar: list[dict[str, Any]]) -> int:
    """
    Yüksek-trafikli paket dinleyici için batch insert.
    Bir tek transaction'da tüm kayıtları yazar (tek-tek insert'ten ~100x hızlı).
    Döndürür: eklenen satır sayısı.
    """
    if not kayitlar:
        return 0
    tam_kayitlar = [{**_TRAFIK_VARSAYILAN, **k} for k in kayitlar]
    with baglanti_al() as bg:
        bg.executemany(_TRAFIK_INSERT_SQL, tam_kayitlar)
        bg.commit()
    return len(tam_kayitlar)


def trafik_kayitlari_id_sonrasi(son_id: int, limit: int = 200) -> list[dict[str, Any]]:
    """
    Verilen ID'den BÜYÜK olan EN YENİ `limit` kaydı ASCENDING sırada döner.

    Yüksek trafikte (saniyede limit'ten fazla paket) eski birikmiş kayıtları
    ATLAR: en yeni `limit` satırı verir, son_id global max'a sıçrar. Böylece
    canlı akış geride kalmaz ve payload sabit kalır (sonsuz birikme/donma yok).
    """
    with baglanti_al() as bg:
        satirlar = [dict(s) for s in bg.execute(
            "SELECT * FROM trafik_kayitlari WHERE id > ? ORDER BY id DESC LIMIT ?",
            (son_id, limit)
        ).fetchall()]
    satirlar.reverse()  # DESC çektik → istemciye ASC (eskiden yeniye) verelim
    return satirlar


def trafik_kayitlarini_getir(
    limit: int = 100,
    eylem_filtresi: str | None = None,
    kaynak_ip_filtresi: str | None = None
) -> list[dict[str, Any]]:
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


def trafik_kayitlari_sorgula(
    filtreler: dict[str, Any] | None = None,
    sayfa: int = 1,
    limit: int = 50,
) -> dict[str, Any]:
    """
    Trafik kayıtlarını filtreleyip SAYFALI döndürür (panel filtre+pagination için).

    filtreler (hepsi opsiyonel):
        eylem        : 'izin' | 'engel'           (izin_ver / engelle+reddet)
        protokoller  : ['tcp','udp','icmp','diger']
        kaynak_ip    : substring (LIKE)
        hedef_ip     : substring (LIKE)
        site         : info/domain substring (LIKE)
        port         : tek port (kaynak VEYA hedef)
        bayraklar    : ['S','A',...] — hepsi pakette bulunmalı
        arayuz       : tam eşleşme
        arama        : serbest metin (kaynak/hedef/info/protokol/bayrak)
        yonetim_gizle: True ise 22/8000 portlarını hariç tut

    Döndürür: {"kayitlar": [...], "toplam": N}
    """
    f = filtreler or {}
    kosullar: list[str] = []
    parametreler: list[Any] = []

    eylem = f.get('eylem')
    if eylem == 'izin':
        kosullar.append("eylem = 'izin_ver'")
    elif eylem == 'engel':
        kosullar.append("eylem IN ('engelle','reddet')")

    protokoller = [p for p in (f.get('protokoller') or []) if p]
    if protokoller:
        parcalar: list[str] = []
        bilinen = [p for p in protokoller if p in ('tcp', 'udp', 'icmp')]
        if bilinen:
            parcalar.append(f"protokol IN ({','.join('?' * len(bilinen))})")
            parametreler += bilinen
        if 'diger' in protokoller:
            parcalar.append("(protokol IS NULL OR protokol NOT IN ('tcp','udp','icmp'))")
        if parcalar:
            kosullar.append("(" + " OR ".join(parcalar) + ")")

    for alan, deger in (('kaynak_ip', f.get('kaynak_ip')),
                        ('hedef_ip', f.get('hedef_ip')),
                        ('info', f.get('site'))):
        if deger:
            kosullar.append(f"{alan} LIKE ?")
            parametreler.append(f"%{deger}%")

    for b in (f.get('bayraklar') or []):
        if b:
            kosullar.append("tcp_bayraklari LIKE ?")
            parametreler.append(f"%{b}%")

    port = f.get('port')
    if port not in (None, ''):
        try:
            p = int(port)
            kosullar.append("(kaynak_port = ? OR hedef_port = ?)")
            parametreler += [p, p]
        except (ValueError, TypeError):
            pass

    if f.get('arayuz'):
        kosullar.append("arayuz = ?")
        parametreler.append(f['arayuz'])

    if f.get('yonetim_gizle'):
        # NULL portlu (ICMP gibi) paketleri eleme; sadece 22/8000 olanları gizle
        kosullar.append("(kaynak_port IS NULL OR kaynak_port NOT IN (22,8000))")
        kosullar.append("(hedef_port IS NULL OR hedef_port NOT IN (22,8000))")

    if f.get('arama'):
        a = f"%{f['arama']}%"
        kosullar.append("(kaynak_ip LIKE ? OR hedef_ip LIKE ? OR info LIKE ? "
                        "OR protokol LIKE ? OR tcp_bayraklari LIKE ?)")
        parametreler += [a, a, a, a, a]

    where = (" WHERE " + " AND ".join(kosullar)) if kosullar else ""
    sayfa = max(1, int(sayfa or 1))
    limit = max(1, int(limit or 50))
    offset = (sayfa - 1) * limit

    with baglanti_al() as bg:
        toplam = bg.execute(
            f"SELECT COUNT(*) FROM trafik_kayitlari{where}", parametreler
        ).fetchone()[0]
        satirlar = [dict(s) for s in bg.execute(
            f"SELECT * FROM trafik_kayitlari{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            parametreler + [limit, offset]
        ).fetchall()]

    return {"kayitlar": satirlar, "toplam": toplam}


def engellenen_denemeler_ozeti(kaynak_limit: int = 8, detay_limit: int = 60) -> dict[str, Any]:
    """
    Yasaklı IP/domainlere erişmeye çalışan kaynakların özeti (grafik + liste için).
    Yalnızca eylem engelle/reddet olan trafik kayıtları.

    Döndürür:
      kaynaklar : [{kaynak_ip, sayi}]  → en çok deneyen kaynaklar (grafik çubukları)
      detaylar  : [{kaynak_ip, hedef, sayi, son}]  → kaynak→hedef kırılımı (liste)
                  hedef = domain (info) varsa o, yoksa hedef_ip
      toplam    : toplam engellenen deneme sayısı
    """
    with baglanti_al() as bg:
        kaynaklar = [dict(r) for r in bg.execute(
            """SELECT kaynak_ip, COUNT(*) AS sayi
               FROM trafik_kayitlari
               WHERE eylem IN ('engelle', 'reddet') AND kaynak_ip IS NOT NULL
               GROUP BY kaynak_ip
               ORDER BY sayi DESC
               LIMIT ?""",
            (kaynak_limit,)
        ).fetchall()]
        detaylar = [dict(r) for r in bg.execute(
            """SELECT kaynak_ip,
                      COALESCE(NULLIF(info, ''), hedef_ip) AS hedef,
                      COUNT(*) AS sayi,
                      MAX(zaman) AS son
               FROM trafik_kayitlari
               WHERE eylem IN ('engelle', 'reddet')
               GROUP BY kaynak_ip, COALESCE(NULLIF(info, ''), hedef_ip)
               ORDER BY sayi DESC
               LIMIT ?""",
            (detay_limit,)
        ).fetchall()]
        toplam = bg.execute(
            "SELECT COUNT(*) FROM trafik_kayitlari WHERE eylem IN ('engelle', 'reddet')"
        ).fetchone()[0]
    return {"kaynaklar": kaynaklar, "detaylar": detaylar, "toplam": toplam}


def supheli_ipler(limit: int = 10) -> dict[str, Any]:
    """
    Şüpheli IP adreslerini puanlayıp döndürür (Sistem Logları grafiği için).

    Sinyaller:
      - Başarısız panel girişleri (brute-force) → giris_kayitlari (basarili=0)
      - Engellenen/reddedilen trafik (yasaklı hedefe erişim) → trafik_kayitlari

    Puan = başarısız_giriş * 5 + engellenen * 1  (giriş denemeleri daha ağır).

    Döndürür: {ipler: [{ip, basarisiz_giris, engellenen, skor, sebep, son}], toplam}
    """
    with baglanti_al() as bg:
        giris_satir = bg.execute(
            """SELECT ip_adresi AS ip, COUNT(*) AS sayi, MAX(zaman) AS son
               FROM giris_kayitlari
               WHERE basarili = 0 AND ip_adresi IS NOT NULL AND ip_adresi != ''
               GROUP BY ip_adresi"""
        ).fetchall()
        blok_satir = bg.execute(
            """SELECT kaynak_ip AS ip, COUNT(*) AS sayi, MAX(zaman) AS son
               FROM trafik_kayitlari
               WHERE eylem IN ('engelle', 'reddet') AND kaynak_ip IS NOT NULL
               GROUP BY kaynak_ip"""
        ).fetchall()

    giris = {r['ip']: {'sayi': r['sayi'], 'son': r['son']} for r in giris_satir}
    blok = {r['ip']: {'sayi': r['sayi'], 'son': r['son']} for r in blok_satir}

    ipler: list[dict[str, Any]] = []
    for ip in set(giris) | set(blok):
        g = giris.get(ip, {}).get('sayi', 0)
        b = blok.get(ip, {}).get('sayi', 0)
        sebepler = []
        if g:
            sebepler.append(f"{g} başarısız giriş")
        if b:
            sebepler.append(f"{b} engellenen erişim")
        sonlar = [x for x in (giris.get(ip, {}).get('son'), blok.get(ip, {}).get('son')) if x]
        ipler.append({
            'ip': ip,
            'basarisiz_giris': g,
            'engellenen': b,
            'skor': g * 5 + b,
            'sebep': ', '.join(sebepler),
            'son': max(sonlar) if sonlar else None,
        })

    ipler.sort(key=lambda x: (x['skor'], x['basarisiz_giris']), reverse=True)
    return {'ipler': ipler[:limit], 'toplam': len(ipler)}


def trafik_istatistiklerini_getir() -> dict[str, Any]:
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


# ══════════════════════════════════════════════════════════════
#  SİSTEM LOGLARI
# ══════════════════════════════════════════════════════════════

def sistem_logu_ekle(olay_turu: str, aciklama: str) -> int:
    """Sistem başlatma, durdurma veya hata olaylarını loglar."""
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO sistem_loglari (olay_turu, aciklama)
               VALUES (?, ?)""",
            (olay_turu, aciklama)
        )
        bg.commit()
        return imle.lastrowid

def sistem_loglari_getir(limit: int = 100, olay_turu: str | None = None) -> list[dict[str, Any]]:
    """Son sistem olaylarını döndürür. İsteğe bağlı olay_turu ile filtrelenebilir."""
    with baglanti_al() as bg:
        if olay_turu:
            return [dict(s) for s in bg.execute(
                "SELECT * FROM sistem_loglari WHERE olay_turu = ? ORDER BY zaman DESC LIMIT ?",
                (olay_turu, limit)
            ).fetchall()]
        else:
            return [dict(s) for s in bg.execute(
                "SELECT * FROM sistem_loglari ORDER BY zaman DESC LIMIT ?",
                (limit,)
            ).fetchall()]

def firewall_durumunu_getir() -> bool:
    """Veritabanındaki son sistem loguna bakarak güvenlik duvarının aktif olup olmadığını anlar."""
    with baglanti_al() as bg:
        son_olay = bg.execute(
            "SELECT olay_turu FROM sistem_loglari WHERE olay_turu IN ('baslangic', 'durma') ORDER BY zaman DESC LIMIT 1"
        ).fetchone()

        # Eğer hiç olay yoksa veya son olay 'baslangic' ise aktiftir (True)
        if not son_olay or son_olay['olay_turu'] == 'baslangic':
            return True
        # Eğer son olay 'durma' ise kapalıdır (False)
        return False


# ══════════════════════════════════════════════════════════════
#  DOSYA İZLEME (File Integrity Monitor)
# ══════════════════════════════════════════════════════════════

def dosya_izleme_tum() -> dict[str, dict[str, Any]]:
    """Baseline kayıtlarını {yol: {ozet, boyut}} olarak döndürür."""
    with baglanti_al() as bg:
        satirlar = bg.execute(
            "SELECT yol, ozet, boyut FROM dosya_izleme"
        ).fetchall()
    return {s["yol"]: {"ozet": s["ozet"], "boyut": s["boyut"]} for s in satirlar}


def dosya_izleme_bos_mu() -> bool:
    """Hiç baseline yoksa True döner (ilk-tarama sessiz yapılır)."""
    with baglanti_al() as bg:
        sayi = bg.execute("SELECT COUNT(*) FROM dosya_izleme").fetchone()[0]
    return sayi == 0


def dosya_izleme_kaydet(yol: str, ozet: str, boyut: int) -> None:
    """Baseline'ı upsert eder."""
    with baglanti_al() as bg:
        bg.execute(
            """INSERT INTO dosya_izleme (yol, ozet, boyut, son_kontrol_t)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(yol) DO UPDATE SET
                   ozet=excluded.ozet,
                   boyut=excluded.boyut,
                   son_kontrol_t=excluded.son_kontrol_t""",
            (yol, ozet, boyut, datetime.now().isoformat())
        )
        bg.commit()


def dosya_izleme_sil(yol: str) -> None:
    """Bir yolu baseline'dan çıkarır (silinmiş dosya için)."""
    with baglanti_al() as bg:
        bg.execute("DELETE FROM dosya_izleme WHERE yol = ?", (yol,))
        bg.commit()


def dosya_degisikligi_ekle(yol: str, degisim_turu: str,
                            eski_ozet: str | None, yeni_ozet: str | None,
                            boyut: int | None) -> int:
    """Yeni bir değişiklik kaydı ekler."""
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO dosya_degisiklikleri
                   (yol, degisim_turu, eski_ozet, yeni_ozet, boyut)
               VALUES (?, ?, ?, ?, ?)""",
            (yol, degisim_turu, eski_ozet, yeni_ozet, boyut)
        )
        bg.commit()
        return imle.lastrowid


def dosya_degisiklikleri_getir(limit: int = 50) -> list[dict[str, Any]]:
    """En yeni dosya değişikliklerini döndürür."""
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(
            "SELECT * FROM dosya_degisiklikleri ORDER BY zaman DESC LIMIT ?",
            (limit,)
        ).fetchall()]


# ══════════════════════════════════════════════════════════════
#  TRAFİK ARŞİVİ (12 saatlik snapshot + sha256 damga)
# ══════════════════════════════════════════════════════════════

def trafik_arsivi_son_kayit_id() -> int:
    """Bir önceki snapshot'ın kapsadığı en büyük trafik_kayitlari.id'sini döndürür.
    Hiç snapshot yoksa 0 döner (ilk arşiv tüm mevcut kayıtları içerir)."""
    with baglanti_al() as bg:
        r = bg.execute(
            "SELECT MAX(son_kayit_id) FROM trafik_arsivi"
        ).fetchone()
    return int(r[0] or 0)


def trafik_arsivi_son_zaman() -> str | None:
    """Son arşivleme anının ISO zamanını döndürür (yoksa None)."""
    with baglanti_al() as bg:
        r = bg.execute(
            "SELECT zaman FROM trafik_arsivi ORDER BY zaman DESC LIMIT 1"
        ).fetchone()
    return r[0] if r else None


def trafik_kayitlari_aralik_getir(min_id_haric: int, limit: int = 1_000_000) -> list[dict[str, Any]]:
    """id > min_id_haric olan trafik kayıtlarını ID'ye göre artan döndürür.
    Arşivleme için kullanılır (sonraki snapshot bu sayede üst üste binmez)."""
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(
            "SELECT * FROM trafik_kayitlari WHERE id > ? ORDER BY id ASC LIMIT ?",
            (min_id_haric, limit)
        ).fetchall()]


def trafik_arsivi_kaydet(dosya_yolu: str, sha256: str, kayit_sayisi: int,
                          ilk_kayit_id: int | None, son_kayit_id: int | None,
                          boyut_byte: int) -> int:
    """Yeni snapshot kaydını ekler."""
    with baglanti_al() as bg:
        imle = bg.execute(
            """INSERT INTO trafik_arsivi
                   (dosya_yolu, sha256, kayit_sayisi, ilk_kayit_id, son_kayit_id, boyut_byte)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (dosya_yolu, sha256, kayit_sayisi, ilk_kayit_id, son_kayit_id, boyut_byte)
        )
        bg.commit()
        return imle.lastrowid


def trafik_arsivi_getir(limit: int = 50) -> list[dict[str, Any]]:
    """En yeni trafik arşiv snapshot'larını döndürür."""
    with baglanti_al() as bg:
        return [dict(s) for s in bg.execute(
            "SELECT * FROM trafik_arsivi ORDER BY zaman DESC LIMIT ?",
            (limit,)
        ).fetchall()]
