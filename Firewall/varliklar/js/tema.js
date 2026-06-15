/**
 * Black Barrier — Tema / Görünüm Uygulayıcı (tema.js)
 * ===================================================
 * Head'de, defer OLMADAN yüklenir → kayıtlı tema rengi ve "hareketleri azalt"
 * tercihi daha sayfa boyanmadan uygulanır (renk titremesi olmaz).
 *
 * Tercihler iki yerde tutulur:
 *   • localStorage  → anlık, cihaza özel uygulama (her sayfa açılışında).
 *   • sunucu (/api/sistem-tercihleri) → cihazlar arası taşınabilirlik (ayarlar.js senkronlar).
 *
 * window.BBTema dışa açılır; ayarlar.js bunu kullanarak canlı önizleme yapar.
 */
(function () {
    'use strict';

    // Her palet, Tailwind'in rgb(var/<alpha-value>) deseni için boşlukla ayrılmış RGB kanalları içerir.
    const PALETLER = {
        mavi:    { ad: 'Mavi',    base: '37 99 235',   acik: '59 130 246',  koyu: '29 78 216',   soluk: '239 246 255' },
        indigo:  { ad: 'İndigo',  base: '79 70 229',   acik: '99 102 241',  koyu: '67 56 202',   soluk: '238 242 255' },
        mor:     { ad: 'Mor',     base: '124 58 237',  acik: '139 92 246',  koyu: '109 40 217',  soluk: '245 243 255' },
        turkuaz: { ad: 'Turkuaz', base: '13 148 136',  acik: '20 184 166',  koyu: '15 118 110',  soluk: '240 253 250' },
        yesil:   { ad: 'Yeşil',   base: '5 150 105',   acik: '16 185 129',  koyu: '4 120 87',    soluk: '236 253 245' },
        kehribar: { ad: 'Kehribar', base: '217 119 6', acik: '245 158 11',  koyu: '180 83 9',    soluk: '255 251 235' },
        turuncu: { ad: 'Turuncu', base: '234 88 12',   acik: '249 115 22',  koyu: '194 65 12',   soluk: '255 247 237' },
        kirmizi: { ad: 'Kırmızı', base: '220 38 38',   acik: '239 68 68',   koyu: '185 28 28',   soluk: '254 242 242' },
        pembe:   { ad: 'Pembe',   base: '219 39 119',  acik: '236 72 153',  koyu: '190 24 93',   soluk: '253 242 248' },
        gri:     { ad: 'Arduvaz', base: '71 85 105',   acik: '100 116 139', koyu: '51 65 85',    soluk: '248 250 252' },
    };

    const VARSAYILAN_RENK = 'mavi';
    const RENK_ANAHTAR    = 'bb_tema_renk';
    const HAREKET_ANAHTAR = 'bb_hareket_azalt';

    function renkUygula(ad) {
        const p = PALETLER[ad] || PALETLER[VARSAYILAN_RENK];
        const k = document.documentElement.style;
        k.setProperty('--bb-birincil-rgb', p.base);
        k.setProperty('--bb-birincil-acik-rgb', p.acik);
        k.setProperty('--bb-birincil-koyu-rgb', p.koyu);
        k.setProperty('--bb-birincil-soluk-rgb', p.soluk);
    }

    function hareketUygula(azalt) {
        document.documentElement.classList.toggle('hareket-azalt', !!azalt);
    }

    // ── Kayıtlı tercihleri HEMEN uygula (sayfa boyanmadan) ──
    renkUygula(localStorage.getItem(RENK_ANAHTAR) || VARSAYILAN_RENK);
    hareketUygula(localStorage.getItem(HAREKET_ANAHTAR) === '1');

    // ── Dışa açılan API ──
    window.BBTema = {
        PALETLER,
        VARSAYILAN_RENK,
        seciliRenk() {
            const ad = localStorage.getItem(RENK_ANAHTAR) || VARSAYILAN_RENK;
            return PALETLER[ad] ? ad : VARSAYILAN_RENK;
        },
        renkAyarla(ad) {
            if (!PALETLER[ad]) ad = VARSAYILAN_RENK;
            localStorage.setItem(RENK_ANAHTAR, ad);
            renkUygula(ad);
        },
        hareketAzaltMi() {
            return localStorage.getItem(HAREKET_ANAHTAR) === '1';
        },
        hareketAyarla(azalt) {
            localStorage.setItem(HAREKET_ANAHTAR, azalt ? '1' : '0');
            hareketUygula(azalt);
        },
    };
})();
