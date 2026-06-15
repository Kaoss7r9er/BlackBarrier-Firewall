# pyright: reportUntypedFunctionDecorator=false
"""
Black Barrier — FastAPI Ana Uygulama (main.py)
=====================================================
Bu dosya db_yonetici.py'nin FastAPI ile nasıl kullanıldığını gösterir.
Aynı zamanda statik HTML dosyalarını sunar.

Çalıştırmak için:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

NOT: Üstteki `# pyright:` direktifi FastAPI'nin @app.get/post/put/delete
decorator'larında strict mode'da çıkan "untyped function decorator"
false-positive'lerini kapatır. FastAPI tip stub'ları yetersiz olduğu için
gereklidir; çalışma zamanı davranışını etkilemez.
"""

import asyncio
import sys
import os
import secrets
import socket
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Callable, Optional
from datetime import datetime, timedelta, timezone
import jwt                  # pip install PyJWT

# ── Proje kök dizinini sys.path'e ekle ─────────────────────────
# main.py "modül/" klasöründe, db_yonetici.py bir üst dizinde.
PROJE_KOK = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJE_KOK))

import db_yonetici as db
import nftables_yonetici as nft
import dhcp_yonetici as dhcp_yon
import baglantili_cihazlar as cihaz_yon
import dosya_izleyici as dosya_izle
import trafik_arsivleyici as trafik_arsiv


def _gizli_anahtar_yukle() -> str:
    """
    JWT gizli anahtarını yükler.
    Öncelik: BB_SECRET_KEY env var > veritabani/.jwt_secret dosyası > yeni üret + dosyaya yaz.

    Dosyaya yazma sebebi: env var ayarlanmadığında her uvicorn yeniden başlatmasında
    farklı bir anahtar üretiliyordu; aktif kullanıcı oturumları geçersiz oluyordu.
    """
    ortam_anahtari = os.environ.get("BB_SECRET_KEY")
    if ortam_anahtari:
        return ortam_anahtari

    anahtar_dosya = PROJE_KOK / "veritabani" / ".jwt_secret"
    if anahtar_dosya.exists():
        return anahtar_dosya.read_text().strip()

    print("[UYARI] BB_SECRET_KEY ortam değişkeni yok. Yeni anahtar üretiliyor ve diske kaydediliyor.")
    print("        Üretim için systemd servisinde BB_SECRET_KEY ayarlanmalı.")
    yeni = secrets.token_hex(32)
    anahtar_dosya.parent.mkdir(parents=True, exist_ok=True)
    anahtar_dosya.write_text(yeni)
    try:
        os.chmod(anahtar_dosya, 0o600)
    except OSError:
        pass  # Windows'ta chmod no-op
    return yeni


# ── Güvenlik Yapılandırması ────────────────────────────────────
GIZLI_ANAHTAR = _gizli_anahtar_yukle()
ALGORITMA: str = "HS256"
TOKEN_SURESI_DK: int = 60  # Token geçerlilik süresi (dakika)

oauth2_sema = OAuth2PasswordBearer(tokenUrl="/api/giris")


# ── Pydantic Modelleri (Input Doğrulama) ───────────────────────

# IPv4 (opsiyonel CIDR ekiyle): "10.0.0.5" veya "192.168.1.0/24"
# Pattern subprocess'e gönderilmeden önce komut güvenliği için doğrulanır.
IPV4_PATTERN = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
# Tek port veya port aralığı: "80" veya "8080-8090"
PORT_PATTERN = r"^\d{1,5}(-\d{1,5})?$"
# Ağ arayüzü adı (enp0s3, eth0, br-lan vb.)
ARAYUZ_PATTERN = r"^[a-zA-Z0-9_.-]{1,16}$"
# DNS adı (RFC-1035'in basit bir alt kümesi): "example.com", "api.v2.foo.co.uk"
DOMAIN_PATTERN = r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
# Saat formatı: HH:MM (00:00 - 23:59)
SAAT_PATTERN = r"^([01]\d|2[0-3]):([0-5]\d)$"


def domain_cozumle(domain: str) -> str | None:
    """
    Domain adını IPv4'e çözer. Başarısızsa None döner.
    Yalnızca ilk A kaydı kullanılır (basit). DNS sorgu hatası yutulur.
    """
    try:
        # gethostbyname IPv4 döndürür; IPv6 için gerekli olursa getaddrinfo'ya geçilebilir
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return None


class GuvenlikKuraliEkle(BaseModel):
    kural_adi: str = Field(..., min_length=1, max_length=100)
    yon: str = Field(..., pattern="^(giris|cikis|ilet|her)$")
    protokol: str = Field(..., pattern="^(tcp|udp|icmp|herhangi)$")
    eylem: str = Field(..., pattern="^(izin_ver|engelle|reddet)$")
    kaynak_ip: Optional[str] = Field(None, pattern=IPV4_PATTERN)
    # Hedef ya doğrudan IP olarak ya da domain (DNS'le çözülür) olarak girilebilir.
    # Eğer hedef_tip='domain' ise hedef_adres bir DNS adı; backend çözüp hedef_ip'ye yazar.
    hedef_tip: str = Field("ip", pattern="^(ip|domain)$")
    hedef_adres: Optional[str] = Field(None, max_length=253)
    kaynak_port: Optional[str] = Field(None, pattern=PORT_PATTERN)
    hedef_port: Optional[str] = Field(None, pattern=PORT_PATTERN)
    oncelik: int = Field(100, ge=1, le=999)
    aktif: bool = True
    # Saat aralığı: ikisi de doluysa kural sadece bu saatler arası uygulanır.
    # İkisi de boşsa "her zaman aktif" anlamına gelir.
    zaman_baslangic: Optional[str] = Field(None, pattern=SAAT_PATTERN)
    zaman_bitis: Optional[str] = Field(None, pattern=SAAT_PATTERN)
    aciklama: Optional[str] = Field(None, max_length=500)


class YonlendirmeKuraliEkle(BaseModel):
    kural_adi: str = Field(..., min_length=1, max_length=100)
    tur: str = Field(..., pattern="^(masquerade|dnat|snat)$")
    protokol: str = Field(..., pattern="^(tcp|udp|herhangi)$")
    dis_arayuz: Optional[str] = Field(default=None, pattern=ARAYUZ_PATTERN)
    ic_arayuz: Optional[str] = Field(default=None, pattern=ARAYUZ_PATTERN)
    dis_port: Optional[str] = Field(default=None, pattern=PORT_PATTERN)
    ic_ip: Optional[str] = Field(default=None, pattern=IPV4_PATTERN)
    ic_port: Optional[str] = Field(default=None, pattern=PORT_PATTERN)
    aciklama: Optional[str] = Field(default=None, max_length=500)


class DhcpAyarGuncelle(BaseModel):
    aktif: bool
    interface_adi: Optional[str] = Field(None, pattern=ARAYUZ_PATTERN)
    alt_ag: Optional[str] = Field(None, pattern=IPV4_PATTERN)
    alt_ag_maskesi: Optional[str] = Field(None, pattern=IPV4_PATTERN)
    havuz_baslangic: Optional[str] = Field(None, pattern=IPV4_PATTERN)
    havuz_bitis: Optional[str] = Field(None, pattern=IPV4_PATTERN)
    ag_gecidi: Optional[str] = Field(None, pattern=IPV4_PATTERN)
    dns_sunuculari: Optional[str] = None  # virgülle ayrılmış, regex tekil IP olmaz
    kira_suresi: int = Field(86400, ge=300)


class KullaniciEkle(BaseModel):
    kullanici_adi: str = Field(..., min_length=2, max_length=50)
    sifre: str = Field(..., min_length=4, max_length=128)
    ad_soyad: str = Field("", max_length=100)
    rol: str = Field("yonetici", pattern="^(admin|yonetici|izleyici)$")


class KullaniciGuncelle(BaseModel):
    ad_soyad: Optional[str] = None
    rol: Optional[str] = Field(None, pattern="^(admin|yonetici|izleyici)$")
    sifre: Optional[str] = None


class SistemTercihiGuncelle(BaseModel):
    tercihler: dict[str, Any]  # {"hostname": "...", "domain": "...", "dark_mode": true}


class SistemLoguEkle(BaseModel):
    olay_turu: str = Field(..., pattern="^(baslangic|durma|yeniden_baslatma|hata|bilgi)$")
    aciklama: str = Field(..., min_length=1, max_length=1000)


# ── JWT Yardımcı Fonksiyonlar ──────────────────────────────────

def token_olustur(kullanici: dict[str, Any]) -> str:
    """Kullanıcı bilgilerini içeren JWT token oluşturur."""
    bitis = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_SURESI_DK)
    payload: dict[str, Any] = {
        "sub": kullanici["kullanici_adi"],
        "uid": kullanici["id"],
        "rol": kullanici.get("rol", "yonetici"),
        "ad_soyad": kullanici.get("ad_soyad", ""),
        "exp": bitis
    }
    return jwt.encode(payload, GIZLI_ANAHTAR, algorithm=ALGORITMA)


def mevcut_kullanici(token: str = Depends(oauth2_sema)) -> dict[str, Any]:
    try:
        veri = jwt.decode(token, GIZLI_ANAHTAR, algorithms=[ALGORITMA])
        kullanici_adi = veri.get("sub")
        if not kullanici_adi:
            raise HTTPException(status_code=401, detail="Geçersiz token")
        return {
            "kullanici_adi": kullanici_adi,
            "uid": veri.get("uid"),
            "rol": veri.get("rol", "yonetici"),
            "ad_soyad": veri.get("ad_soyad", "")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token süresi dolmuş")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token doğrulanamadı")


def yetki_ister(*izinli_roller: str) -> Callable[..., dict[str, Any]]:
    """
    Dependency factory: yalnızca belirtilen rollere izin verir.

    Kullanım:
        @app.post("/api/kullanicilar", dependencies=[Depends(yetki_ister("admin"))])
        async def ...

    İzleyici rolü (salt okunur) hiçbir yazma endpoint'ine giremez; bu factory
    döndürdüğü dependency yalnızca yazma/silme endpoint'lerinde kullanılmalıdır.
    GET endpoint'leri için sadece `Depends(mevcut_kullanici)` yeterlidir.
    """
    izinli_set = set(izinli_roller)

    def _kontrol(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)) -> dict[str, Any]:
        if aktif_kullanici.get("rol") not in izinli_set:
            raise HTTPException(
                status_code=403,
                detail=f"Bu işlem için yetkiniz yok. Gereken rol: {', '.join(sorted(izinli_set))}"
            )
        return aktif_kullanici

    return _kontrol


# ── Uygulama Yaşam Döngüsü (Lifespan) ────────────────────────

@asynccontextmanager
async def yasam_dongusu(app: FastAPI):
    """Uvicorn başlarken veritabanını hazırla ve kalıcı kuralları nftables'a uygula."""
    db.veritabanini_baslat()

    # Dosya bütünlüğü taraması: ilk kez (baseline boş) sessiz baseline doldurur,
    # sonraki başlatmalarda deploy/manuel düzenlemelerle değişen dosyaları yakalar.
    try:
        ozet = dosya_izle.tarama_yap(zorla=True)
        if any(ozet[k] for k in ("yeni", "degisti", "silindi")):
            print(f"[başlangıç] Dosya taraması: {ozet['yeni']} yeni, "
                  f"{ozet['degisti']} değişti, {ozet['silindi']} silindi")
    except Exception as e:
        print(f"[uyarı] Dosya tarama hatası: {e}")

    # Kural kalıcılığı (PDF taslağı, "Komut İşleyişi Kural Kalıcılığı" bölümü):
    # Servis her başladığında DB'deki tüm aktif kuralları nftables çekirdeğine
    # tekrar uygular. Böylece reboot/restart sonrası DB ↔ kernel senkron kalır.
    #
    # ANCAK: kullanıcı güvenlik duvarını panelden KAPATTIYSA (son sistem olayı
    # 'durma'), restart sonrası kuralları geri yükleyip onun kararını ezmeyiz —
    # zincirler boş bırakılır (policy accept = serbest akış).
    firewall_acik = db.firewall_durumunu_getir()
    kurallar = db.kurallari_getir(sadece_aktif=True)
    yonlendirmeler = db.yonlendirme_kurallari_getir(sadece_aktif=True)

    if nft.NFTABLES_DEVRE_DISI:
        print("[başlangıç] BB_NFTABLES_DISABLED=1 — komutlar yalnızca yazdırılacak.")
        nft.tum_kurallari_uygula(kurallar)
        nft.tum_yonlendirme_kurallarini_uygula(yonlendirmeler)
    elif not nft.nftables_kullanilabilir_mi():
        print("[uyarı] 'nft' binary'si bulunamadı. Kurallar DB'de tutulacak ama")
        print("        nftables'a uygulanmayacak. Çözüm: 'sudo apt install nftables'")
        print("        veya geliştirici modunda 'BB_NFTABLES_DISABLED=1' ayarla.")
    elif firewall_acik:
        print(f"[başlangıç] Güvenlik duvarı AÇIK — {len(kurallar)} filter kuralı + "
              f"{len(yonlendirmeler)} yönlendirme kuralı nftables'a uygulanıyor...")
        nft.tum_kurallari_uygula(kurallar)
        nft.tum_yonlendirme_kurallarini_uygula(yonlendirmeler)
    else:
        print("[başlangıç] Güvenlik duvarı KAPALI (son olay 'durma') — kurallar "
              "uygulanmıyor, zincirler temiz bırakılıyor.")
        nft.firewall_durdur()

    # DHCP + DNS engelleme yapılandırması: DB'deki dhcp_ayarlari + domain engelleme
    # kurallarını dnsmasq config'ine çevirip servisi yeniden başlat.
    dhcp_ayarlari = db.tum_dhcp_ayarlarini_getir()
    engelli_domainler = db.engelli_domainleri_getir()
    print(f"[başlangıç] {len(dhcp_ayarlari)} DHCP yapılandırması + "
          f"{len(engelli_domainler)} engelli domain dnsmasq'a uygulanıyor...")
    if dhcp_yon.DHCP_DEVRE_DISI:
        print("[başlangıç] BB_DHCP_DISABLED=1 — dnsmasq config yalnızca yazdırılacak.")
        dhcp_yon.tum_dhcp_yapilandirmasini_uygula(dhcp_ayarlari, engelli_domainler)
    elif dhcp_yon.dnsmasq_kullanilabilir_mi():
        dhcp_yon.tum_dhcp_yapilandirmasini_uygula(dhcp_ayarlari, engelli_domainler)
    else:
        print("[uyarı] 'dnsmasq' binary'si bulunamadı. DHCP ayarları DB'de tutulacak")
        print("        ama gerçek DHCP servisi çalışmayacak. Çözüm: 'sudo apt install dnsmasq'")
        print("        veya geliştirici modunda 'BB_DHCP_DISABLED=1' ayarla.")

    # Trafik arşivi: her 12 saatte bir trafik_kayitlari snapshot'ı + sha256 damga.
    # Restart sonrası "kalan süreyi" hesaplayıp gerekirse hemen arşivler.
    arsiv_gorev = asyncio.create_task(trafik_arsiv.arka_plan_dongusu())

    yield  # Uygulama çalışıyor

    # Background görevini düzgün kapat
    arsiv_gorev.cancel()
    try:
        await arsiv_gorev
    except (asyncio.CancelledError, Exception):
        pass

    print("[DB] Uygulama kapatılıyor...")


# ── Uygulama Oluşturma ────────────────────────────────────────

app = FastAPI(
    title="Black Barrier API",
    version="1.0",
    lifespan=yasam_dongusu
)

# CORS Middleware — Panel aynı uvicorn sunucusundan servis edildiği için
# yalnızca yerel kaynaklara izin verilir. Ek origin gerekirse BB_CORS_ORIGINS
# ortam değişkeniyle virgülle ayrılmış olarak verilir (örn: "https://ag.example.com").
CORS_KOKENLERI = ["http://localhost:8000", "http://127.0.0.1:8000"]
_ek_cors = os.environ.get("BB_CORS_ORIGINS", "").strip()
if _ek_cors:
    CORS_KOKENLERI.extend(k.strip() for k in _ek_cors.split(",") if k.strip())

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_KOKENLERI,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Statik Dosya Sunumu ────────────────────────────────────────
# HTML, CSS, JS dosyalarını sunmak için
app.mount("/varliklar", StaticFiles(directory=str(PROJE_KOK / "varliklar")), name="varliklar")


# ── Sayfa Endpoint'leri (HTML Sunumu) ──────────────────────────

@app.get("/", include_in_schema=False)
async def anasayfa():
    return FileResponse(str(PROJE_KOK / "index.html"))


@app.get("/{sayfa_adi}.html", include_in_schema=False)
async def sayfa_sun(sayfa_adi: str):
    dosya = PROJE_KOK / f"{sayfa_adi}.html"
    if not dosya.exists():
        raise HTTPException(404, "Sayfa bulunamadı")
    return FileResponse(str(dosya))


# ══════════════════════════════════════════════════════════════
#  KİMLİK DOĞRULAMA API
# ══════════════════════════════════════════════════════════════

@app.post("/api/giris")
async def giris(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    """Kullanıcı girişi — başarılıysa JWT token döndürür."""
    # İstemci bilgilerini al (log için)
    istemci_ip = request.client.host if request.client else "bilinmiyor"
    user_agent = request.headers.get("user-agent", "bilinmiyor")

    kullanici = db.kullanici_dogrula(form.username, form.password)
    if not kullanici:
        # Başarısız giriş logu
        db.giris_kaydi_ekle(
            kullanici_id=None,
            kullanici_adi=form.username,
            ip_adresi=istemci_ip,
            user_agent=user_agent,
            basarili=False
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya şifre hatalı"
        )

    # Başarılı giriş logu
    db.giris_kaydi_ekle(
        kullanici_id=kullanici["id"],
        kullanici_adi=kullanici["kullanici_adi"],
        ip_adresi=istemci_ip,
        user_agent=user_agent,
        basarili=True
    )

    token = token_olustur(kullanici)
    return {"access_token": token, "token_type": "bearer"}


# ══════════════════════════════════════════════════════════════
#  KULLANICI YÖNETİMİ API
# ══════════════════════════════════════════════════════════════

@app.get("/api/kullanicilar")
async def kullanicilari_listele(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    """Tüm kullanıcıları listeler."""
    return db.kullanicilari_getir()


@app.post("/api/kullanicilar", status_code=201)
async def kullanici_olustur(
    veri: KullaniciEkle,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin"))
):
    """Yeni kullanıcı oluşturur. Sadece admin."""
    try:
        yeni_id = db.kullanici_olustur(
            kullanici_adi=veri.kullanici_adi,
            sifre=veri.sifre,
            rol=veri.rol,
            ad_soyad=veri.ad_soyad
        )
        return {"id": yeni_id, "mesaj": "Kullanıcı oluşturuldu"}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(409, "Bu kullanıcı adı zaten mevcut")
        raise HTTPException(500, f"Kullanıcı oluşturulamadı: {e}")


@app.put("/api/kullanicilar/{kullanici_id}")
async def kullanici_duzenle(
    kullanici_id: int,
    veri: KullaniciGuncelle,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin"))
):
    """Mevcut kullanıcıyı günceller. Sadece admin."""
    try:
        basarili = db.kullanici_guncelle(
            kullanici_id=kullanici_id,
            ad_soyad=veri.ad_soyad or "",
            rol=veri.rol,
            sifre=veri.sifre
        )
        if not basarili:
            raise HTTPException(404, "Kullanıcı bulunamadı")
        return {"mesaj": "Kullanıcı başarıyla güncellendi"}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Kullanıcı güncellenemedi: {e}")


@app.delete("/api/kullanicilar/{kullanici_id}")
async def kullanici_kaldir(
    kullanici_id: int,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin"))
):
    """Kullanıcıyı siler. Sadece admin. Kendini silemez."""
    if aktif_kullanici.get("uid") == kullanici_id:
        raise HTTPException(400, "Kendi hesabınızı silemezsiniz")
    if not db.kullanici_sil(kullanici_id):
        raise HTTPException(404, "Kullanıcı bulunamadı")
    return {"mesaj": "Kullanıcı silindi"}


# ══════════════════════════════════════════════════════════════
#  SİSTEM TERCİHLERİ API
# ══════════════════════════════════════════════════════════════

@app.get("/api/sistem-tercihleri")
async def sistem_tercihlerini_getir(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    """Mevcut kullanıcının tercihlerini döndürür."""
    # uid mevcut_kullanici'de JWT'den daima ayarlanır; direct indexing 'int' tipini verir
    return db.sistem_tercihleri_getir(int(aktif_kullanici["uid"]))


@app.put("/api/sistem-tercihleri")
async def sistem_tercihlerini_kaydet(
    veri: SistemTercihiGuncelle,
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
):
    """Kullanıcı tercihlerini kaydeder."""
    uid = int(aktif_kullanici["uid"])
    for anahtar, deger in veri.tercihler.items():
        db.sistem_tercihi_kaydet(uid, anahtar, str(deger))
    return {"mesaj": "Tercihler kaydedildi"}


# ══════════════════════════════════════════════════════════════
#  GÜVENLİK KURALLARI API
# ══════════════════════════════════════════════════════════════

@app.get("/api/kurallar")
async def kurallari_listele(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    # Panelde TÜM kurallar gösterilmeli (pasif olanlar dahil) — yoksa bir kural
    # pasifleştirilince listeden kaybolur. nftables'a uygulama tarafı zaten
    # ayrıca sadece_aktif=True ile süzüyor.
    return db.kurallari_getir(sadece_aktif=False)


def _nft_yenile() -> dict[str, Any]:
    """DB'deki aktif kuralları nftables'a yeniden uygula. Sonuç dict döner."""
    basarili, basarisiz = nft.tum_kurallari_uygula(
        db.kurallari_getir(sadece_aktif=True)
    )
    return {"nft_uygulanan": basarili, "nft_basarisiz": basarisiz}


def _dnsmasq_yenile() -> None:
    """
    Domain engelleme kuralları değişince dnsmasq DNS blocklist'ini yeniden uygula.
    DNS yalnızca engelli domain varsa açılır (yoksa port=0). youtube gibi
    çok-IP'li adresler ancak DNS seviyesinde güvenilir engellenebilir.
    """
    if dhcp_yon.DHCP_DEVRE_DISI or dhcp_yon.dnsmasq_kullanilabilir_mi():
        dhcp_yon.tum_dhcp_yapilandirmasini_uygula(
            db.tum_dhcp_ayarlarini_getir(),
            db.engelli_domainleri_getir(),
        )


@app.post("/api/kurallar", status_code=201)
async def kural_olustur(
    veri: GuvenlikKuraliEkle,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin", "yonetici"))
) -> dict[str, Any]:
    """
    Yeni güvenlik kuralı ekler.

    hedef_adres alanı:
      - hedef_tip='ip'     → IPv4 olmalı, doğrudan hedef_ip'ye yazılır
      - hedef_tip='domain' → DNS'le çözülür, sonuç hedef_ip'ye, orijinal isim hedef_domain'a yazılır
    """
    veri_dict = veri.model_dump()

    # Hedef adresi normalize et: IP mi domain mi?
    hedef_adres = veri_dict.pop("hedef_adres", None)
    hedef_tip = veri_dict.get("hedef_tip", "ip")
    hedef_ip: str | None = None
    hedef_domain: str | None = None

    if hedef_adres:
        hedef_adres = hedef_adres.strip()
        if hedef_tip == "domain":
            # Domain formatını kontrol et
            import re
            if not re.match(DOMAIN_PATTERN, hedef_adres):
                raise HTTPException(400, f"Geçersiz domain formatı: '{hedef_adres}'")
            cozulen = domain_cozumle(hedef_adres)
            if not cozulen:
                raise HTTPException(400, f"Domain çözümlenemedi: '{hedef_adres}'")
            hedef_ip = cozulen
            hedef_domain = hedef_adres
        else:
            # IP olarak verilen alan; yine IPv4 regex'iyle doğrula
            import re
            if not re.match(IPV4_PATTERN, hedef_adres):
                raise HTTPException(400, f"Geçersiz IP/CIDR formatı: '{hedef_adres}'")
            hedef_ip = hedef_adres

    veri_dict["hedef_ip"] = hedef_ip
    veri_dict["hedef_domain"] = hedef_domain

    yeni_id = db.kural_ekle(veri_dict)
    nft_sonuc = _nft_yenile()
    # Domain engelleme → DNS blocklist'ini de güncelle (çok-IP'li adresler için)
    if hedef_tip == "domain":
        _dnsmasq_yenile()
    return {
        "id": yeni_id,
        "mesaj": "Kural eklendi",
        "cozulmus_ip": hedef_ip if hedef_tip == "domain" else None,
        **nft_sonuc
    }


@app.delete("/api/kurallar/{kural_id}")
async def kural_kaldir(
    kural_id: int,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin", "yonetici"))
) -> dict[str, Any]:
    if not db.kural_sil(kural_id):
        raise HTTPException(404, "Kural bulunamadı")
    nft_sonuc = _nft_yenile()
    # Silinen kural domain olabilir → DNS blocklist'ini senkronla
    _dnsmasq_yenile()
    return {"mesaj": "Kural silindi", **nft_sonuc}


@app.patch("/api/kurallar/{kural_id}/durum")
async def kural_durum_guncelle(
    kural_id: int,
    aktif: bool,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin", "yonetici"))
) -> dict[str, Any]:
    if not db.kural_durum_degistir(kural_id, aktif):
        raise HTTPException(404, "Kural bulunamadı")
    nft_sonuc = _nft_yenile()
    # Aktif/pasif değişimi domain kuralını etkilemiş olabilir → DNS'i senkronla
    _dnsmasq_yenile()
    return {"mesaj": "Kural durumu güncellendi", **nft_sonuc}


# ── Yönlendirme Endpoint'leri ──────────────────────────────────

def _nft_yonlendirme_yenile() -> dict[str, Any]:
    """DB'deki aktif yönlendirme kurallarını nftables'a yeniden uygula."""
    basarili, basarisiz = nft.tum_yonlendirme_kurallarini_uygula(
        db.yonlendirme_kurallari_getir(sadece_aktif=True)
    )
    return {"nft_uygulanan": basarili, "nft_basarisiz": basarisiz}


@app.get("/api/yonlendirme")
async def yonlendirme_listele(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    return db.yonlendirme_kurallari_getir()


@app.post("/api/yonlendirme", status_code=201)
async def yonlendirme_ekle(
    veri: YonlendirmeKuraliEkle,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin", "yonetici"))
) -> dict[str, Any]:
    yeni_id = db.yonlendirme_kurali_ekle(veri.model_dump())
    nft_sonuc = _nft_yonlendirme_yenile()
    return {"id": yeni_id, "mesaj": "Yönlendirme kuralı eklendi", **nft_sonuc}


@app.delete("/api/yonlendirme/{kural_id}")
async def yonlendirme_kaldir(
    kural_id: int,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin", "yonetici"))
) -> dict[str, Any]:
    if not db.yonlendirme_kurali_sil(kural_id):
        raise HTTPException(404, "Kural bulunamadı")
    nft_sonuc = _nft_yonlendirme_yenile()
    return {"mesaj": "Yönlendirme kuralı silindi", **nft_sonuc}


# ── DHCP Endpoint'leri ─────────────────────────────────────────

def _dhcp_yenile() -> dict[str, Any]:
    """
    DB'deki tüm DHCP ayarlarını dnsmasq config'ine yazıp servisi yeniden başlatır.
    Domain engelleme blocklist'ini de dahil eder — yoksa DHCP ayarı kaydedince
    config yeniden üretilirken domain engelleri silinirdi.
    """
    basarili, aktif_sayi = dhcp_yon.tum_dhcp_yapilandirmasini_uygula(
        db.tum_dhcp_ayarlarini_getir(),
        db.engelli_domainleri_getir(),
    )
    return {"dhcp_uygulandi": basarili, "dhcp_aktif_yapilandirma": aktif_sayi}


@app.get("/api/dhcp/{arayuz}")
async def dhcp_ayarlari(arayuz: str, aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    ayarlar = db.dhcp_ayarlarini_getir(arayuz)
    if not ayarlar:
        raise HTTPException(404, "Arayüz bulunamadı")
    return ayarlar


@app.put("/api/dhcp/{arayuz}")
async def dhcp_guncelle(
    arayuz: str,
    veri: DhcpAyarGuncelle,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin", "yonetici"))
) -> dict[str, Any]:
    db.dhcp_ayarlarini_kaydet(arayuz, veri.model_dump())
    dhcp_sonuc = _dhcp_yenile()
    return {"mesaj": "DHCP ayarları güncellendi", **dhcp_sonuc}


@app.get("/api/dhcp/{arayuz}/kiralamalar")
async def kiralamalar(arayuz: str, aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    """
    dnsmasq lease dosyasını parse eder (/var/lib/misc/dnsmasq.leases).
    Lease dosyasında interface bilgisi olmadığı için tüm kiralamalar döner.
    Üretimde subnet karşılaştırmasıyla filtrelenebilir.
    """
    ayar = db.dhcp_ayarlarini_getir(arayuz)
    iface = (ayar or {}).get("interface_adi")
    return dhcp_yon.aktif_kiralamalar(iface)


# ── Bağlı Cihazlar Endpoint'i ───────────────────────────────────

@app.get("/api/baglantili-cihazlar")
async def baglantili_cihazlar(
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
) -> list[dict[str, Any]]:
    """
    Firewall'a görünen yerel ağ cihazlarını döndürür.
    Kaynak: DHCP lease (dnsmasq) + ARP komşu tablosu, MAC ile birleştirilmiş.
    """
    return cihaz_yon.cihazlari_topla()


# ── Trafik ve Panel Endpoint'leri ──────────────────────────────

@app.get("/api/trafik")
async def trafik_loglari(
    eylem: Optional[str] = None,        # 'izin' | 'engel'
    protokol: Optional[str] = None,     # virgüllü: "tcp,udp,..."
    kaynak_ip: Optional[str] = None,
    hedef_ip: Optional[str] = None,
    site: Optional[str] = None,
    port: Optional[str] = None,
    bayrak: Optional[str] = None,       # virgüllü: "S,A,..."
    arayuz: Optional[str] = None,
    arama: Optional[str] = None,
    yonetim_gizle: bool = True,
    sayfa: int = 1,
    limit: int = 50,
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
) -> dict[str, Any]:
    """
    Trafik kayıtlarını filtreleyip SAYFALI döndürür.
    Filtre uygulanınca panel tüm eşleşmeleri sayfa sayfa gezebilir (200 sınırı yok).
    Döndürür: {kayitlar, toplam, sayfa, limit}
    """
    limit = max(10, min(int(limit), 500))
    sayfa = max(1, int(sayfa))
    filtreler = {
        'eylem': eylem,
        'protokoller': [x.strip() for x in (protokol or '').split(',') if x.strip()],
        'kaynak_ip': (kaynak_ip or '').strip() or None,
        'hedef_ip': (hedef_ip or '').strip() or None,
        'site': (site or '').strip() or None,
        'port': (port or '').strip() or None,
        'bayraklar': [x.strip() for x in (bayrak or '').split(',') if x.strip()],
        'arayuz': (arayuz or '').strip() or None,
        'arama': (arama or '').strip() or None,
        'yonetim_gizle': yonetim_gizle,
    }
    sonuc = db.trafik_kayitlari_sorgula(filtreler, sayfa, limit)
    sonuc['sayfa'] = sayfa
    sonuc['limit'] = limit
    return sonuc


@app.get("/api/trafik/engellenen")
async def trafik_engellenen_ozet(
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
) -> dict[str, Any]:
    """
    Yasaklı IP/domainlere erişmeye çalışan kaynakların özeti (grafik + liste).
    Döndürür: {kaynaklar, detaylar, toplam}
    """
    return db.engellenen_denemeler_ozeti()


@app.get("/api/panel/ozet")
async def panel_ozeti(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    return db.trafik_istatistiklerini_getir()


# ── Sistem Logları Endpoint'leri ──────────────────────────────

@app.get("/api/sistem-loglari")
async def sistem_loglari_listele(limit: int = 20, olay_turu: Optional[str] = None, aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    """Panel üzerinden sistem olaylarını görüntülemek için."""
    return db.sistem_loglari_getir(limit=limit, olay_turu=olay_turu)


@app.get("/api/dosya-degisiklikleri")
async def dosya_degisiklikleri_listele(
    limit: int = 50,
    tara: int = 1,
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
) -> dict[str, Any]:
    """
    Dosya bütünlüğü değişiklik kayıtlarını döndürür.
    `tara=1` (varsayılan) ise istek anında bir tarama tetiklenir; throttle
    sayesinde 5 sn içinde tekrar çağırmak tekrar tarama yapmaz.

    Döndürür: {"degisiklikler": [...], "tarama": {...}}
    """
    tarama_ozeti = None
    if tara:
        try:
            tarama_ozeti = dosya_izle.tarama_yap()
        except Exception as e:
            tarama_ozeti = {"hata": str(e)}
    return {
        "degisiklikler": db.dosya_degisiklikleri_getir(limit=max(1, min(limit, 500))),
        "tarama": tarama_ozeti,
    }


@app.get("/api/trafik/arsiv")
async def trafik_arsiv_listele(
    limit: int = 50,
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
) -> dict[str, Any]:
    """
    12 saatlik trafik snapshot'larının listesini döndürür (en yeniden eskiye).
    Her kayıtta dosya yolu, sha256, kayıt sayısı, boyut ve zaman bulunur.
    """
    return {"arsivler": db.trafik_arsivi_getir(limit=max(1, min(limit, 500)))}


@app.post("/api/trafik/arsiv/calistir", status_code=200)
async def trafik_arsiv_manuel(
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin"))
) -> dict[str, Any]:
    """
    Manuel arşivleme tetikleyici (admin). 12 saati beklemeden anında bir
    snapshot oluşturur. Yeni trafik kaydı yoksa snapshot atlanır.
    """
    # Senkron iş; uzun değil (bir kaç MB üst sınır) ama yine de threadpool'a at
    sonuc = await asyncio.to_thread(trafik_arsiv.bir_kez_calistir)
    return sonuc


@app.get("/api/guvenlik/supheli-ipler")
async def supheli_ipler_listele(
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)
) -> dict[str, Any]:
    """
    Şüpheli IP adresleri: başarısız panel girişleri + engellenen erişim
    denemelerine göre puanlanmış liste (Sistem Logları grafiği için).
    Döndürür: {ipler, toplam}
    """
    return db.supheli_ipler()

@app.post("/api/sistem-loglari", status_code=201)
async def sistem_logu_kaydet(
    veri: SistemLoguEkle,
    request: Request,
    aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici),
):
    """
    Panelden log eklemek için. JWT zorunludur.

    Bash scriptlerinin (baslat.sh gibi) artık API'ye değil, doğrudan db_yonetici
    aracılığıyla SQLite'a yazması gerekir — bu endpoint dış erişime kapalıdır.
    """
    yeni_id = db.sistem_logu_ekle(veri.olay_turu, veri.aciklama)
    return {"id": yeni_id, "mesaj": "Sistem logu eklendi"}


# ── Firewall Kontrol Endpoint'leri ────────────────────────────

class FirewallDurum(BaseModel):
    aktif: bool
    neden: Optional[str] = None
    tahmini_sure: Optional[str] = None

@app.get("/api/firewall/durum")
async def firewall_durum_oku(aktif_kullanici: dict[str, Any] = Depends(mevcut_kullanici)):
    """Güvenlik duvarının anlık durumunu getirir (sekronizasyon için)."""
    return {"aktif": db.firewall_durumunu_getir()}

@app.post("/api/firewall/durum")
async def firewall_durum_degistir(
    veri: FirewallDurum,
    aktif_kullanici: dict[str, Any] = Depends(yetki_ister("admin"))
) -> dict[str, Any]:
    """
    Güvenlik duvarını tamamen açıp kapatmak için. Sadece admin.

    Kapat: 3 filter zincirini flush eder; varsayılan policy 'accept' olduğu için
    trafik serbestçe akar (kurallar 'devre dışı'). DB'deki kurallar korunur.
    Aç:    DB'deki tüm aktif kuralları nftables'a yeniden uygular.
    """
    if not veri.aktif:
        nft.firewall_durdur()
        aciklama_metni = (
            f"DURDURULDU: {veri.neden} (Tahmini Süre: {veri.tahmini_sure}) "
            f"- Kapatan: {aktif_kullanici['kullanici_adi']}"
        )
        db.sistem_logu_ekle("durma", aciklama_metni)
        return {"mesaj": "Güvenlik duvarı başarıyla devre dışı bırakıldı."}
    else:
        basarili, basarisiz = nft.firewall_baslat(
            db.kurallari_getir(sadece_aktif=True),
            db.yonlendirme_kurallari_getir(sadece_aktif=True),
        )
        aciklama_metni = (
            f"BAŞLATILDI: Güvenlik duvarı manuel olarak aktifleştirildi "
            f"({basarili} kural uygulandı). - Açan: {aktif_kullanici['kullanici_adi']}"
        )
        db.sistem_logu_ekle("baslangic", aciklama_metni)
        return {
            "mesaj": "Güvenlik duvarı başarıyla aktif edildi.",
            "nft_uygulanan": basarili,
            "nft_basarisiz": basarisiz,
        }
