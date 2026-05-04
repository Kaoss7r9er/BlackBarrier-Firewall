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
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kullanicilar (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kullanici_adi TEXT    NOT NULL UNIQUE,
    sifre_hash    TEXT    NOT NULL,           -- bcrypt hash
    rol           TEXT    NOT NULL DEFAULT 'admin', -- 'admin' | 'izleyici'
    olusturma_t   TEXT    NOT NULL DEFAULT (datetime('now')),
    son_giris_t   TEXT
);

-- ------------------------------------------------------------
-- 2. GÜVENLİK KURALLARI (nftables)
--    Sistem her yeniden başladığında bu tablo okunarak
--    kurallar nftables'a yeniden uygulanır.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guvenlik_kurallari (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kural_adi     TEXT    NOT NULL,
    yon           TEXT    NOT NULL CHECK(yon IN ('giris','cikis','ilet')), -- INPUT/OUTPUT/FORWARD
    protokol      TEXT    NOT NULL CHECK(protokol IN ('tcp','udp','icmp','herhangi')),
    kaynak_ip     TEXT,                       -- NULL = tüm kaynaklar
    hedef_ip      TEXT,                       -- NULL = tüm hedefler
    kaynak_port   TEXT,                       -- NULL = tüm portlar, örn: "80" veya "8080-8090"
    hedef_port    TEXT,
    eylem         TEXT    NOT NULL CHECK(eylem IN ('izin_ver','engelle','reddet')),
    oncelik       INTEGER NOT NULL DEFAULT 100, -- küçük = önce işle
    aktif         INTEGER NOT NULL DEFAULT 1,   -- 1=aktif, 0=devre dışı
    aciklama      TEXT,
    olusturma_t   TEXT    NOT NULL DEFAULT (datetime('now')),
    guncelleme_t  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Servis başlarken aktif kuralları sıralı çekmek için index
CREATE INDEX IF NOT EXISTS idx_kural_oncelik
    ON guvenlik_kurallari (aktif, oncelik);

-- ------------------------------------------------------------
-- 3. YÖNLENDİRME KURALLARI (NAT / Port Yönlendirme)
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
-- 4. DHCP AYARLARI
--    Her ağ arayüzü için bir satır tutulur.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dhcp_ayarlari (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    arayuz          TEXT    NOT NULL UNIQUE,  -- 'LAN', 'OPT_VLAN_1' vb.
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
-- 5. DHCP KİRALAMALARI (Aktif Leases)
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
-- 6. TRAFİK KAYITLARI (Firewall Logs)
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
    aciklama        TEXT
);

-- Son kayıtları hızlı çekmek için index
CREATE INDEX IF NOT EXISTS idx_trafik_zaman
    ON trafik_kayitlari (zaman DESC);
