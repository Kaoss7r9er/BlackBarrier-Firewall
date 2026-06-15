/**
 * Black Barrier — Ayarlar Sekmesi
 * ================================
 * İki tür tercih yönetir:
 *   1) Cihaz bilgileri (hostname, domain, dil, saat_dilimi) — form alanları, Kaydet ile sunucuya yazılır.
 *   2) Görünüm/panel tercihleri (tema_renk, hareket_azalt, acilis_sayfasi, kenar_cubugu_dar)
 *      — kontroller değişince ANINDA uygulanır (localStorage + DOM) ve ayrıca Kaydet ile
 *        sunucuya da yazılır (cihazlar arası taşınabilirlik için).
 *
 * Sunucu tarafı /api/sistem-tercihleri jenerik anahtar/değer saklar (kullanıcıya özel),
 * bu yüzden yeni anahtarlar backend değişikliği gerektirmez.
 */

document.addEventListener('DOMContentLoaded', () => {

    // ── Cihaz bilgisi form alanları ──
    const CIHAZ_HARITASI = {
        hostname: 'ayarHostname',
        domain: 'ayarDomain',
        dil: 'ayarDil',
        saat_dilimi: 'ayarSaatDilimi',
    };

    const btnKaydet     = document.getElementById('btnAyarlarKaydet');
    const durumKutusu   = document.getElementById('ayarlarDurum');
    const renkPaleti    = document.getElementById('temaRenkPaleti');
    const hareketToggle = document.getElementById('ayarHareketAzalt');
    const acilisSelect  = document.getElementById('ayarAcilisSayfasi');
    const kenarToggle   = document.getElementById('ayarKenarCubuguDar');

    const LS_ACILIS = 'bb_acilis_sayfasi';
    const LS_KENAR  = 'bb_kenar_cubugu_dar';

    function dogruMu(v) {
        return v === true || v === '1' || v === 1 || v === 'true';
    }

    // ═══════════════════════════════════════
    //  DURUM MESAJI
    // ═══════════════════════════════════════
    function durumGoster(metin, tip = 'basari') {
        if (!durumKutusu) return;
        durumKutusu.textContent = metin;
        durumKutusu.classList.remove('hidden', 'bg-green-50', 'text-durum-basarili',
                                      'bg-red-50', 'text-durum-kritik');
        durumKutusu.classList.add(tip === 'basari'
            ? 'bg-green-50' : 'bg-red-50',
            tip === 'basari' ? 'text-durum-basarili' : 'text-durum-kritik');
        setTimeout(() => durumKutusu.classList.add('hidden'), 3000);
    }

    // ═══════════════════════════════════════
    //  TEMA RENGİ PALETİ
    // ═══════════════════════════════════════
    function paletiOlustur() {
        if (!renkPaleti || !window.BBTema || renkPaleti.childElementCount) return;
        Object.entries(window.BBTema.PALETLER).forEach(([ad, p]) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'bb-renk-swatch w-9 h-9 rounded-full flex items-center justify-center transition-transform hover:scale-110 focus:outline-none';
            btn.style.backgroundColor = `rgb(${p.base})`;
            btn.setAttribute('data-renk', ad);
            btn.title = p.ad;
            btn.innerHTML = '<span class="material-symbols-outlined text-white text-lg bb-renk-tik" style="display:none">check</span>';
            btn.addEventListener('click', () => {
                window.BBTema.renkAyarla(ad);
                paletiVurgula();
            });
            renkPaleti.appendChild(btn);
        });
    }

    function paletiVurgula() {
        if (!renkPaleti || !window.BBTema) return;
        const secili = window.BBTema.seciliRenk();
        renkPaleti.querySelectorAll('.bb-renk-swatch').forEach(sw => {
            const aktif = sw.getAttribute('data-renk') === secili;
            sw.classList.toggle('ring-2', aktif);
            sw.classList.toggle('ring-offset-2', aktif);
            sw.classList.toggle('ring-metin-birincil', aktif);
            const tik = sw.querySelector('.bb-renk-tik');
            if (tik) tik.style.display = aktif ? '' : 'none';
        });
    }

    // ═══════════════════════════════════════
    //  GÖRÜNÜM/PANEL KONTROLLERİNİ DOM'A YANSIT
    // ═══════════════════════════════════════
    function gorunumKontrolleriniGuncelle() {
        paletiVurgula();
        if (hareketToggle && window.BBTema) hareketToggle.checked = window.BBTema.hareketAzaltMi();
        if (acisVar()) acilisSelect.value = localStorage.getItem(LS_ACILIS) || 'dashboard';
        if (kenarToggle) kenarToggle.checked = localStorage.getItem(LS_KENAR) === '1';
    }
    function acisVar() { return !!acilisSelect; }

    // ── Canlı uygulama (kontrol değişince) ──
    if (hareketToggle) {
        hareketToggle.addEventListener('change', () => {
            if (window.BBTema) window.BBTema.hareketAyarla(hareketToggle.checked);
        });
    }
    if (acilisSelect) {
        acilisSelect.addEventListener('change', () => {
            localStorage.setItem(LS_ACILIS, acilisSelect.value);
        });
    }
    if (kenarToggle) {
        kenarToggle.addEventListener('change', () => {
            localStorage.setItem(LS_KENAR, kenarToggle.checked ? '1' : '0');
            // Anında uygula
            const sidebar = document.getElementById('sidebar');
            if (sidebar) {
                if (kenarToggle.checked) {
                    sidebar.classList.add('collapsed');
                    sidebar.style.width = '60px';
                } else {
                    sidebar.classList.remove('collapsed');
                    sidebar.style.width = '260px';
                }
            }
        });
    }

    // ═══════════════════════════════════════
    //  SUNUCUDAN YÜKLE
    // ═══════════════════════════════════════
    async function ayarlariYukle() {
        paletiOlustur();
        try {
            const yanit = await Oturum.apiIstegi('/api/sistem-tercihleri');
            if (yanit && yanit.ok) {
                const t = await yanit.json();

                // Cihaz bilgisi alanları
                Object.entries(CIHAZ_HARITASI).forEach(([anahtar, id]) => {
                    const el = document.getElementById(id);
                    if (el && t[anahtar] !== undefined && t[anahtar] !== null) el.value = t[anahtar];
                });

                // Görünüm/panel tercihleri → localStorage'a senkronla + uygula
                if (window.BBTema && t.tema_renk) window.BBTema.renkAyarla(t.tema_renk);
                if (window.BBTema && t.hareket_azalt !== undefined) window.BBTema.hareketAyarla(dogruMu(t.hareket_azalt));
                if (t.acilis_sayfasi) localStorage.setItem(LS_ACILIS, t.acilis_sayfasi);
                if (t.kenar_cubugu_dar !== undefined) localStorage.setItem(LS_KENAR, dogruMu(t.kenar_cubugu_dar) ? '1' : '0');
            }
        } catch (hata) {
            console.error("Ayarlar yüklenemedi:", hata);
        }
        gorunumKontrolleriniGuncelle();
    }

    // ═══════════════════════════════════════
    //  KAYDET (hepsini sunucuya yaz)
    // ═══════════════════════════════════════
    async function ayarlariKaydet() {
        const tercihler = {};

        // Cihaz bilgileri
        Object.entries(CIHAZ_HARITASI).forEach(([anahtar, id]) => {
            const el = document.getElementById(id);
            if (el) tercihler[anahtar] = el.value.trim();
        });

        // Görünüm/panel tercihleri (güncel durumdan)
        if (window.BBTema) {
            tercihler.tema_renk = window.BBTema.seciliRenk();
            tercihler.hareket_azalt = window.BBTema.hareketAzaltMi() ? '1' : '0';
        }
        tercihler.acilis_sayfasi = localStorage.getItem(LS_ACILIS) || 'dashboard';
        tercihler.kenar_cubugu_dar = localStorage.getItem(LS_KENAR) === '1' ? '1' : '0';

        if (btnKaydet) {
            btnKaydet.disabled = true;
            btnKaydet.innerHTML = '<span class="material-symbols-outlined text-base animate-spin">progress_activity</span> Kaydediliyor...';
        }

        try {
            const yanit = await Oturum.apiIstegi('/api/sistem-tercihleri', {
                method: 'PUT',
                body: JSON.stringify({ tercihler }),
            });
            if (yanit && yanit.ok) {
                durumGoster('Ayarlar başarıyla kaydedildi', 'basari');
            } else {
                const err = yanit ? await yanit.json() : null;
                durumGoster((err && err.detail) || 'Kayıt başarısız', 'hata');
            }
        } catch (hata) {
            console.error("Ayarlar kaydedilemedi:", hata);
            durumGoster('Bağlantı hatası', 'hata');
        } finally {
            if (btnKaydet) {
                btnKaydet.disabled = false;
                btnKaydet.innerHTML = '<span class="material-symbols-outlined text-base">save</span> Kaydet';
            }
        }
    }

    if (btnKaydet) {
        btnKaydet.addEventListener('click', (e) => {
            e.preventDefault();
            ayarlariKaydet();
        });
    }

    document.addEventListener('sekmeYuklendi:ayarlar', ayarlariYukle);
});
