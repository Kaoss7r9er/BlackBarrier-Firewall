/**
 * Black Barrier — Merkezi Oturum Yönetimi (oturum.js)
 * ====================================================
 * Tüm panel sayfalarında include edilerek:
 *  1. Token yoksa giriş sayfasına yönlendirir
 *  2. Token payload'ından kullanıcı bilgilerini çıkarır
 *  3. Profil alanlarını otomatik doldurur
 *  4. API isteklerine Authorization header ekler
 *  5. Çıkış fonksiyonu sağlar
 */

const Oturum = (function () {
    'use strict';

    const TOKEN_ANAHTAR = 'bb_token';
    const KULLANICI_ANAHTAR = 'bb_kullanici';
    const GIRIS_SAYFASI = '/';

    // ── Token İşlemleri ─────────────────────────────────

    function tokenAl() {
        return localStorage.getItem(TOKEN_ANAHTAR);
    }

    function tokenPayloadCoz(token) {
        try {
            const parcalar = token.split('.');
            if (parcalar.length !== 3) return null;
            const payload = JSON.parse(atob(parcalar[1]));
            return payload;
        } catch (e) {
            return null;
        }
    }

    function tokenSuresiDolduMu(payload) {
        if (!payload || !payload.exp) return true;
        const simdi = Math.floor(Date.now() / 1000);
        return simdi >= payload.exp;
    }

    // ── Oturum Kontrolü ─────────────────────────────────

    function oturumKontrol() {
        const token = tokenAl();
        if (!token) {
            cikisYap();
            return null;
        }

        const payload = tokenPayloadCoz(token);
        if (!payload || tokenSuresiDolduMu(payload)) {
            cikisYap();
            return null;
        }

        return {
            kullanici_adi: payload.sub || '',
            uid: payload.uid || 0,
            rol: payload.rol || 'yonetici',
            ad_soyad: payload.ad_soyad || '',
            basHarfler: basHarfHesapla(payload.ad_soyad || payload.sub || 'BB')
        };
    }

    function basHarfHesapla(isim) {
        if (!isim) return 'BB';
        const parcalar = isim.trim().split(/\s+/);
        if (parcalar.length >= 2) {
            return (parcalar[0][0] + parcalar[1][0]).toUpperCase();
        }
        return isim.substring(0, 2).toUpperCase();
    }

    // ── Rol / Yetki Yardımcıları ────────────────────────────
    // Backend her yazma endpoint'inde rolü zaten zorlar (yetki_ister). Bunlar
    // yalnızca UI'da yazma kontrollerini gizlemek/pasifleştirmek içindir.
    function _aktifRol() {
        const b = window._oturumBilgisi || oturumKontrol();
        return b ? (b.rol || 'yonetici') : null;
    }
    function yazabilir() {
        const r = _aktifRol();
        return r === 'admin' || r === 'yonetici';
    }
    function adminMi() {
        return _aktifRol() === 'admin';
    }
    function izleyiciMi() {
        return _aktifRol() === 'izleyici';
    }

    function rolEtiketiAl(rol) {
        const etiketler = {
            'admin':    { metin: 'Admin', renk: 'bg-red-100 text-red-700' },
            'yonetici': { metin: 'Yönetici', renk: 'bg-blue-100 text-blue-700' },
            'izleyici': { metin: 'İzleyici', renk: 'bg-slate-100 text-slate-600' }
        };
        const lower = (rol || '').toLowerCase();
        return etiketler[lower] || { metin: rol || 'Bilinmiyor', renk: 'bg-slate-100 text-slate-600' };
    }

    // ── Profil Alanlarını Doldur ─────────────────────────

    function profilDoldur(bilgi) {
        if (!bilgi) return;

        const ad = bilgi.ad_soyad || bilgi.kullanici_adi || '—';
        const etiket = rolEtiketiAl(bilgi.rol);

        // Baş harfler (küçük avatar + menü/ayarlar büyük avatar)
        document.querySelectorAll('.profil-bh, .profil-bh-buyuk').forEach(el => {
            el.textContent = bilgi.basHarfler;
        });
        // İsim alanları (menü + sidebar + ayarlar kartı)
        document.querySelectorAll('.profil-isim, .profil-kullanici-adi').forEach(el => {
            el.textContent = ad;
        });
        // Kullanıcı adı (@handle) alanları
        document.querySelectorAll('.profil-kadi').forEach(el => {
            el.textContent = bilgi.kullanici_adi || '';
        });
        // Rol etiketleri
        document.querySelectorAll('.profil-rol, .profil-rol-adi').forEach(el => {
            el.textContent = etiket.metin;
        });
    }

    // ── API İstekleri ───────────────────────────────────

    async function apiIstegi(url, secenek = {}) {
        const token = tokenAl();
        if (!token) {
            cikisYap();
            return null;
        }

        const varsayilan = {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                ...(secenek.headers || {})
            }
        };

        const birlesik = { ...secenek, headers: varsayilan.headers };

        try {
            const yanit = await fetch(url, birlesik);
            if (yanit.status === 401) {
                cikisYap();
                return null;
            }
            return yanit;
        } catch (hata) {
            console.error('[Oturum] API hatası:', hata);
            return null;
        }
    }

    // ── Çıkış ───────────────────────────────────────────

    function cikisYap() {
        localStorage.removeItem(TOKEN_ANAHTAR);
        localStorage.removeItem(KULLANICI_ANAHTAR);
        // Giriş sayfasındaysak yönlendirme yapma
        if (!window.location.pathname.endsWith('index.html') && window.location.pathname !== '/') {
            window.location.href = GIRIS_SAYFASI;
        }
    }

    // ── Sayfa Yüklendiğinde Çalıştır ────────────────────

    function baslat() {
        const bilgi = oturumKontrol();
        if (!bilgi) return null;

        profilDoldur(bilgi);

        // Çıkış butonlarını bağla
        document.querySelectorAll('.cikis-btn, [data-cikis]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                cikisYap();
            });
        });

        return bilgi;
    }

    // ── Public API ──────────────────────────────────────

    return {
        baslat,
        tokenAl,
        apiIstegi,
        cikisYap,
        oturumKontrol,
        rolEtiketiAl,
        basHarfHesapla,
        yazabilir,
        adminMi,
        izleyiciMi
    };

})();

// Sayfa yüklendiğinde otomatik başlat
document.addEventListener('DOMContentLoaded', () => {
    window._oturumBilgisi = Oturum.baslat();
});
