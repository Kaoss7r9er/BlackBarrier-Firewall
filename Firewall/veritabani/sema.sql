-- ============================================================
--  Black Barrier Güvenlik Duvarı — SQLite Veritabanı Şeması
--  Dosya: veritabani/sema.sql
-- ============================================================

PRAGMA journal_mode = WAL;   -- Eş zamanlı okuma/yazma için
PRAGMA foreign_keys = ON;    -- İlişkisel bütünlük kontrolü

-- ------------------------------------------------------------
-- 1. KULLANICILAR
--    Yönetici hesapları. Şifreler bcrypt ile hashlenir,
--    düz metin ASLA saklanmaz.
--    rol: 'admin' (tam yetki), 'yonetici' (kullanıcı yönetimi hariç),
--         'izleyici' (salt okunur)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kullanicilar (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kullanici_adi TEXT    NOT NULL UNIQUE,
    sifre_hash    TEXT    NOT NULL,           -- bcrypt hash
    ad_soyad      TEXT    DEFAULT '',         -- Görünen isim
    rol           TEXT    NOT NULL DEFAULT 'yonetici'
                  CHECK(rol IN ('admin','yonetici','izleyici')),
    olusturma_t   TEXT    NOT NULL DEFAULT (datetime('now')),
    son_giris_t   TEXT
);

-- ------------------------------------------------------------
-- 3. GÜVENLİK KURALLARI (nftables)
--    Sistem her yeniden başladığında bu tablo okunarak
--    kurallar nftables'a yeniden uygulanır.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guvenlik_kurallari (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kural_adi     TEXT    NOT NULL,
    yon           TEXT    NOT NULL CHECK(yon IN ('giris','cikis','ilet','her')), -- INPUT/OUTPUT/FORWARD/HEPSİ (her=3 zincire birden)
    protokol      TEXT    NOT NULL CHECK(protokol IN ('tcp','udp','icmp','herhangi')),
    kaynak_ip     TEXT,                       -- NULL = tüm kaynaklar
    hedef_ip      TEXT,                       -- NULL = tüm hedefler (IP olarak saklanır; domain girilirse çözülmüş hali yazılır)
    hedef_tip     TEXT    DEFAULT 'ip' CHECK(hedef_tip IN ('ip','domain')),  -- Kullanıcı domain girdiyse 'domain'; nftables yine IP üzerinden çalışır
    hedef_domain  TEXT,                       -- Kullanıcının yazdığı orijinal domain (debug/UI için)
    kaynak_port   TEXT,                       -- NULL = tüm portlar, örn: "80" veya "8080-8090"
    hedef_port    TEXT,
    eylem         TEXT    NOT NULL CHECK(eylem IN ('izin_ver','engelle','reddet')),
    oncelik       INTEGER NOT NULL DEFAULT 100, -- küçük = önce işle
    aktif         INTEGER NOT NULL DEFAULT 1,   -- 1=aktif, 0=devre dışı
    zaman_baslangic TEXT,                     -- "HH:MM" formatında; doluysa kural sadece bu saatler arası uygulanır
    zaman_bitis   TEXT,                       -- "HH:MM"
    aciklama      TEXT,
    olusturma_t   TEXT    NOT NULL DEFAULT (datetime('now')),
    guncelleme_t  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Servis başlarken aktif kuralları sıralı çekmek için index
CREATE INDEX IF NOT EXISTS idx_kural_oncelik
    ON guvenlik_kurallari (aktif, oncelik);

-- ------------------------------------------------------------
-- 4. YÖNLENDİRME KURALLARI (NAT / Port Yönlendirme)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS yonlendirme_kurallari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kural_adi       TEXT    NOT NULL,
    tur             TEXT    NOT NULL CHECK(tur IN ('masquerade','dnat','snat')),
    protokol        TEXT    NOT NULL CHECK(protokol IN ('tcp','udp','herhangi')),
    dis_arayuz      TEXT,                     -- WAN arayüzü, örn: "eth0"
    ic_arayuz       TEXT,                     -- LAN arayüzü, örn: "eth1"
    dis_port        TEXT,                     -- Dışarıdan gelen port
    ic_ip           TEXT,                     -- Yönlendirilecek iç IP
    ic_port         TEXT,                     -- İç IP'deki hedef port
    aktif           INTEGER NOT NULL DEFAULT 1,
    aciklama        TEXT,
    olusturma_t     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------
-- 5. DHCP AYARLARI
--    Her ağ arayüzü için bir satır tutulur.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dhcp_ayarlari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arayuz          TEXT    NOT NULL UNIQUE,  -- Sembolik ad: 'LAN', 'OPT_VLAN_1' vb.
    interface_adi   TEXT,                     -- Sistem interface adı: enp0s8, eth1 vb. (dnsmasq için)
    aktif           INTEGER NOT NULL DEFAULT 0,
    alt_ag          TEXT,                     -- örn: 192.168.1.0
    alt_ag_maskesi  TEXT,                     -- örn: 255.255.255.0
    havuz_baslangic TEXT,                     -- örn: 192.168.1.100
    havuz_bitis     TEXT,                     -- örn: 192.168.1.200
    ag_gecidi       TEXT,                     -- Gateway IP
    dns_sunuculari  TEXT,                     -- virgülle ayrılmış, örn: "8.8.8.8,1.1.1.1"
    kira_suresi     INTEGER NOT NULL DEFAULT 86400, -- saniye cinsinden (varsayılan: 1 gün)
    guncelleme_t    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Varsayılan arayüzleri ekle
INSERT OR IGNORE INTO dhcp_ayarlari (arayuz, aktif)
    VALUES ('LAN', 0), ('OPT_VLAN_1', 0);

-- ------------------------------------------------------------
-- 6. DHCP KİRALAMALARI (Aktif Leases)
--    Arayüzdeki "Aktif İstemci Kiralamaları" tablosunu doldurur.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dhcp_kiralamalari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arayuz          TEXT    NOT NULL,
    ip_adresi       TEXT    NOT NULL,
    mac_adresi      TEXT    NOT NULL,
    host_adi        TEXT,
    kira_baslangic  TEXT    NOT NULL DEFAULT (datetime('now')),
    kira_bitis      TEXT    NOT NULL,
    durum           TEXT    NOT NULL DEFAULT 'aktif'
                    CHECK(durum IN ('aktif','suresi_dolmus','rezerve'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_kira_mac_arayuz
    ON dhcp_kiralamalari (mac_adresi, arayuz);

-- ------------------------------------------------------------
-- 7. TRAFİK KAYITLARI (Firewall Logs)
--    Engellenen veya izin verilen bağlantıların logu.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trafik_kayitlari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    zaman           TEXT    NOT NULL DEFAULT (datetime('now')),
    kural_id        INTEGER REFERENCES guvenlik_kurallari(id) ON DELETE SET NULL,
    eylem           TEXT    NOT NULL CHECK(eylem IN ('izin_ver','engelle','reddet')),
    protokol        TEXT,
    kaynak_ip       TEXT,
    kaynak_port     INTEGER,
    hedef_ip        TEXT,
    hedef_port      INTEGER,
    arayuz          TEXT,
    paket_boyutu    INTEGER,
    tcp_bayraklari  TEXT,        -- "SA" (SYN+ACK), "F" (FIN), "R" (RST) gibi
    ttl             INTEGER,     -- IP TTL (Linux 64, Windows 128 vs.)
    aciklama        TEXT,
    info            TEXT         -- IP'ye karşılık gelen domain (DNS snooping) — "site" bilgisi
);

-- Son kayıtları hızlı çekmek için index
CREATE INDEX IF NOT EXISTS idx_trafik_zaman
    ON trafik_kayitlari (zaman DESC);

-- ------------------------------------------------------------
-- 8. GİRİŞ KAYITLARI (Oturum Logları)
--    Kim, ne zaman, hangi cihazdan giriş yaptı.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS giris_kayitlari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kullanici_id    INTEGER REFERENCES kullanicilar(id) ON DELETE CASCADE,
    kullanici_adi   TEXT    NOT NULL,
    ip_adresi       TEXT,
    user_agent      TEXT,
    basarili        INTEGER NOT NULL DEFAULT 1,  -- 1=başarılı, 0=başarısız
    zaman           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_giris_zaman
    ON giris_kayitlari (zaman DESC);

-- ------------------------------------------------------------
-- 9. SİSTEM TERCİHLERİ (Kullanıcı Bazlı Kalıcı Ayarlar)
--    Her kullanıcının kendi tercihleri ayrı tutulur.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sistem_tercihleri (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kullanici_id    INTEGER NOT NULL REFERENCES kullanicilar(id) ON DELETE CASCADE,
    anahtar         TEXT    NOT NULL,
    deger           TEXT,
    guncelleme_t    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(kullanici_id, anahtar)
);

-- ------------------------------------------------------------
-- 10. SİSTEM LOGLARI (Sistem Olayları & Yeniden Başlatma Nedenleri)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sistem_loglari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    olay_turu       TEXT    NOT NULL CHECK(olay_turu IN ('baslangic', 'durma', 'yeniden_baslatma', 'hata', 'bilgi')),
    aciklama        TEXT    NOT NULL,
    zaman           TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sistem_loglari_zaman
    ON sistem_loglari (zaman DESC);

-- ------------------------------------------------------------
-- 11. DOSYA İZLEME (File Integrity Monitoring — FIM)
--    İzlenen proje dosyalarının baseline hash'i. dosya_izleyici.py
--    her tarama sonrası bu tabloyu güncel tutar.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dosya_izleme (
    yol            TEXT PRIMARY KEY,           -- PROJE_KOK'a göre göreceli yol
    ozet           TEXT NOT NULL,              -- sha256 hex
    boyut          INTEGER,                    -- byte
    son_kontrol_t  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------
-- 12. DOSYA DEĞİŞİKLİKLERİ (Değişim Logu)
--    "şu tarihte bu dosyada değişiklik oldu" — sistem loglarının
--    yanında ayrı bir akış olarak gösterilir (panel'de Sistem Logları sekmesi).
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dosya_degisiklikleri (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    yol            TEXT NOT NULL,
    degisim_turu   TEXT NOT NULL CHECK(degisim_turu IN ('yeni','degisti','silindi')),
    eski_ozet      TEXT,                       -- hash (silindi/degisti için dolu)
    yeni_ozet      TEXT,                       -- hash (yeni/degisti için dolu)
    boyut          INTEGER,
    zaman          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dosya_deg_zaman
    ON dosya_degisiklikleri (zaman DESC);

-- ------------------------------------------------------------
-- 13. TRAFİK ARŞİVİ (Periyodik Snapshot + SHA256 Damga)
--    trafik_arsivleyici.py her 12 saatte bir önceki snapshot'tan
--    sonraki trafik_kayitlari satırlarını JSON olarak diske yazar,
--    sha256 özetini sidecar dosyaya ve bu tabloya kaydeder.
--    Amaç: olay sonrası kanıt koruma + bütünlük doğrulaması.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trafik_arsivi (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dosya_yolu    TEXT NOT NULL,                -- PROJE_KOK'a göre göreceli yol
    sha256        TEXT NOT NULL,                -- snapshot içeriğinin hex sha256'sı
    kayit_sayisi  INTEGER NOT NULL,
    ilk_kayit_id  INTEGER,                      -- snapshot'taki ilk trafik_kayitlari.id
    son_kayit_id  INTEGER,                      -- son trafik_kayitlari.id (sonraki snapshot bunun üstünden başlar)
    boyut_byte    INTEGER NOT NULL,
    zaman         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_trafik_arsivi_zaman
    ON trafik_arsivi (zaman DESC);
