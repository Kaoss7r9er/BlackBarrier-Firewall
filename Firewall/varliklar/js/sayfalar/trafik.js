/**
 * Black Barrier — Trafik Kayıtları (DB-tabanlı, filtreli + sayfalı)
 * ================================================================
 * GET /api/trafik?<filtreler>&sayfa=N&limit=L  →  {kayitlar, toplam, sayfa, limit}
 *
 * Davranış:
 *   - Canlı: SAYFA 1'deyken her POLL_MS'de bir otomatik yenilenir (Duraklat ile durur).
 *   - Filtre uygulanınca TÜM eşleşmeler SAYFA SAYFA gezilir (eski 200 sınırı yok).
 *   - Filtreler SUNUCU tarafında uygulanır (kaynak/hedef/site/port/proto/bayrak/eylem).
 *   - Sayfa > 1 iken otomatik yenileme durur (gezinirken satırlar kaymasın).
 */
document.addEventListener('DOMContentLoaded', () => {

    const POLL_MS = 2000;

    // ── DOM: başlık ────────────────────────────────────────────
    const tblGovde = document.getElementById('tblTrafikGovde');
    const bosMesaj = document.getElementById('trafikBosMesaj');
    const canliIkon = document.getElementById('trafikCanliIkon');
    const durumMetniEl = document.getElementById('trafikDurumMetni');
    const sayacEl = document.getElementById('trafikSayac');
    const btnDuraklat = document.getElementById('btnTrafikDuraklat');
    const btnDuraklatMetin = document.getElementById('btnTrafikDuraklatMetin');
    const btnYenile = document.getElementById('btnTrafikYenile');
    const btnDisaAktar = document.getElementById('btnTrafikDisaAktar');
    const btnGorunumBasit = document.getElementById('btnGorunumBasit');
    const btnGorunumDetayli = document.getElementById('btnGorunumDetayli');

    // Engellenen erişim denemeleri özeti (grafik + liste)
    const btnEngellenenOzet = document.getElementById('btnEngellenenOzet');
    const btnEngellenenOk = document.getElementById('btnEngellenenOk');
    const engellenenPanel = document.getElementById('engellenenPanel');
    const engellenenGrafik = document.getElementById('engellenenGrafik');
    const engellenenListe = document.getElementById('engellenenListe');
    const engellenenToplam = document.getElementById('engellenenToplam');

    // ── DOM: filtreler ─────────────────────────────────────────
    const filtreArama = document.getElementById('filtreArama');
    const filtreEylem = document.getElementById('filtreEylem');
    const filtreKaynakIP = document.getElementById('filtreKaynakIP');
    const filtreHedefIP = document.getElementById('filtreHedefIP');
    const filtreSite = document.getElementById('filtreSite');
    const filtrePort = document.getElementById('filtrePort');
    const filtreYonetimGizle = document.getElementById('filtreYonetimGizle');
    const filtreSayac = document.getElementById('filtreSayac');
    const btnFiltreSifirla = document.getElementById('btnFiltreSifirla');
    const btnFiltreAc = document.getElementById('btnFiltreAc');
    const filtrePanel = document.getElementById('filtrePanel');
    const filtreRozet = document.getElementById('filtreRozet');
    const filtreOkIkon = document.getElementById('filtreOkIkon');
    const protoChipler = document.getElementById('protoChipler');
    const bayrakChipler = document.getElementById('bayrakChipler');

    // ── DOM: sayfalama ─────────────────────────────────────────
    const trafikToplamMetni = document.getElementById('trafikToplamMetni');
    const trafikSayfaMetni = document.getElementById('trafikSayfaMetni');
    const trafikSayfaBoyutu = document.getElementById('trafikSayfaBoyutu');
    const btnSayfaIlk = document.getElementById('btnSayfaIlk');
    const btnSayfaOnceki = document.getElementById('btnSayfaOnceki');
    const btnSayfaSonraki = document.getElementById('btnSayfaSonraki');
    const btnSayfaSon = document.getElementById('btnSayfaSon');

    // ── Durum ──────────────────────────────────────────────────
    let sayfa = 1;
    let limit = 50;
    let toplam = 0;
    let canli = true;
    let pollHandle = null;
    let yukleniyor = false;
    let detayli = false;   // Basit (false) / Detaylı (true) görünüm — teknik sütunlar
    let engellenenAcik = false;   // engellenen özet paneli açık mı
    let engellenenPollHandle = null;
    const secilenProtokoller = new Set();   // 'tcp','udp','icmp','diger'
    const secilenBayraklar = new Set();      // 'S','A','F','R','P','U'

    // ── Render yardımcıları ────────────────────────────────────
    function tarihKisalt(iso) {
        if (!iso) return '—';
        try {
            const t = new Date(iso);
            return t.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch { return '—'; }
    }

    const EYLEM_GORUNUM = {
        'izin_ver': { etiket: 'İzin',       cls: 'bg-green-50 text-durum-basarili', satirCls: '' },
        'engelle':  { etiket: 'Engellendi', cls: 'bg-red-50 text-durum-kritik',     satirCls: 'bg-red-50/30' },
        'reddet':   { etiket: 'Reddedildi', cls: 'bg-orange-50 text-durum-uyari',   satirCls: 'bg-orange-50/30' },
    };

    const PROTO_RENK = {
        'tcp':  { cls: 'bg-blue-50 text-blue-700' },
        'udp':  { cls: 'bg-purple-50 text-purple-700' },
        'icmp': { cls: 'bg-orange-50 text-orange-700' },
    };

    function bayrakRoz(flags) {
        if (!flags) return '<span class="text-metin-ucuncul">—</span>';
        const renkler = {
            'S': 'text-green-600', 'A': 'text-blue-600', 'F': 'text-orange-600',
            'R': 'text-durum-kritik', 'P': 'text-purple-600', 'U': 'text-pink-600',
        };
        return [...flags].map(c => {
            const cls = renkler[c] || 'text-metin-ucuncul';
            return `<span class="${cls} font-bold">${c}</span>`;
        }).join('');
    }

    // DNS'ten gelen domain bilgisi güvenilmez sayılır → HTML escape (XSS koruması)
    function kacisHTML(s) {
        return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    }

    function paketSatiri(k, sira) {
        const eylem = EYLEM_GORUNUM[k.eylem] || { satirCls: '' };
        const protokolKucuk = (k.protokol || '').toLowerCase();
        const proto = PROTO_RENK[protokolKucuk] || { cls: 'bg-slate-100 text-metin-ikincil' };
        const protokolEtiketi = (k.protokol || 'any').toUpperCase();

        const kaynak = k.kaynak_ip || 'any';
        const kaynakPort = k.kaynak_port ? `:${k.kaynak_port}` : '';
        const hedef = k.hedef_ip || 'any';
        const hedefPort = k.hedef_port ? `:${k.hedef_port}` : '';
        const boyut = k.paket_boyutu ? `${k.paket_boyutu}` : '—';
        const ttl = (k.ttl !== null && k.ttl !== undefined) ? `${k.ttl}` : '—';
        const bayrak = bayrakRoz(k.tcp_bayraklari);

        const info = (k.info || '').trim();
        const infoMetin = info
            ? `<span class="text-birincil font-medium" title="${kacisHTML(info)}">${kacisHTML(info)}</span>`
            : '<span class="text-metin-ucuncul">—</span>';

        // Durum rozeti: İzin (yeşil) / Engellendi (kırmızı) / Reddedildi (turuncu)
        const durumBadge = `<span class="px-1.5 py-0.5 ${eylem.cls || 'bg-slate-100 text-metin-ikincil'} rounded-full text-2xs font-semibold whitespace-nowrap">${eylem.etiket || (k.eylem || '?')}</span>`;

        let kuralEtiketi;
        if (k.kural_id !== null && k.kural_id !== undefined) {
            const renkCls = (k.eylem === 'engelle' || k.eylem === 'reddet')
                ? 'text-durum-kritik font-bold' : 'text-birincil';
            kuralEtiketi = `<span class="${renkCls}">#${k.kural_id}</span>`;
        } else if (k.aciklama === 'pcap') {
            kuralEtiketi = '<span class="text-2xs text-metin-ucuncul italic">pcap</span>';
        } else {
            kuralEtiketi = '<span class="text-metin-ucuncul">—</span>';
        }

        const row = document.createElement('tr');
        row.className = `hover:bg-slate-100 transition-colors text-xs ${eylem.satirCls}`;
        row.innerHTML = `
            <td class="kolon-detay px-2 py-1 text-metin-ucuncul font-kod">${sira}</td>
            <td class="px-2 py-1 text-metin-ucuncul">${tarihKisalt(k.zaman)}</td>
            <td class="kolon-detay px-2 py-1 text-metin-ikincil">${k.arayuz || '—'}</td>
            <td class="px-2 py-1 font-kod text-metin-birincil">${kaynak}<span class="text-metin-ucuncul">${kaynakPort}</span></td>
            <td class="px-2 py-1 font-kod text-metin-birincil">${hedef}<span class="text-metin-ucuncul">${hedefPort}</span></td>
            <td class="px-2 py-1 max-w-[180px] truncate">${infoMetin}</td>
            <td class="px-2 py-1">${durumBadge}</td>
            <td class="px-2 py-1"><span class="px-1.5 py-0.5 ${proto.cls} rounded text-2xs font-bold">${protokolEtiketi}</span></td>
            <td class="kolon-detay px-2 py-1 font-kod">${bayrak}</td>
            <td class="kolon-detay px-2 py-1 text-metin-ucuncul font-kod text-2xs">${ttl}</td>
            <td class="kolon-detay px-2 py-1 text-metin-ucuncul">${boyut}</td>
            <td class="px-2 py-1">${kuralEtiketi}</td>
        `;
        return row;
    }

    // ── Filtreleri sorgu dizisine çevir ────────────────────────
    function sorguDizisi() {
        const p = new URLSearchParams();
        const e = filtreEylem?.value || '';  // '' | 'izin' | 'engel'
        if (e) p.set('eylem', e);
        const ara = (filtreArama?.value || '').trim(); if (ara) p.set('arama', ara);
        if (secilenProtokoller.size) p.set('protokol', [...secilenProtokoller].join(','));
        if (secilenBayraklar.size) p.set('bayrak', [...secilenBayraklar].join(','));
        const ki = (filtreKaynakIP?.value || '').trim(); if (ki) p.set('kaynak_ip', ki);
        const hi = (filtreHedefIP?.value || '').trim(); if (hi) p.set('hedef_ip', hi);
        const si = (filtreSite?.value || '').trim(); if (si) p.set('site', si);
        const po = (filtrePort?.value || '').trim(); if (po) p.set('port', po);
        p.set('yonetim_gizle', filtreYonetimGizle?.checked ? 'true' : 'false');
        p.set('sayfa', String(sayfa));
        p.set('limit', String(limit));
        return p.toString();
    }

    // Panel içindeki aktif (varsayılandan sapan) filtre sayısı → "Filtreler (N)" rozeti
    function aktifFiltreSayisi() {
        let n = 0;
        if ((filtreKaynakIP?.value || '').trim()) n++;
        if ((filtreHedefIP?.value || '').trim()) n++;
        if ((filtreSite?.value || '').trim()) n++;
        if ((filtrePort?.value || '').trim()) n++;
        if (secilenProtokoller.size) n++;
        if (secilenBayraklar.size) n++;
        if (filtreYonetimGizle && !filtreYonetimGizle.checked) n++;
        return n;
    }

    function rozetGuncelle() {
        if (!filtreRozet) return;
        const n = aktifFiltreSayisi();
        filtreRozet.textContent = String(n);
        filtreRozet.classList.toggle('hidden', n === 0);
    }

    // Kullanıcı sonuçları daralttı mı? (yönetim-gizle varsayılan olduğu için sayılmaz)
    // Filtre VARSA → sayfalama; YOKSA → sınırlı canlı görünüm (sayfasız).
    function filtreVarMi() {
        return !!(
            (filtreArama?.value || '').trim() ||
            (filtreEylem?.value || '') ||
            (filtreKaynakIP?.value || '').trim() ||
            (filtreHedefIP?.value || '').trim() ||
            (filtreSite?.value || '').trim() ||
            (filtrePort?.value || '').trim() ||
            secilenProtokoller.size ||
            secilenBayraklar.size
        );
    }

    // ── Basit / Detaylı sütun görünürlüğü ──────────────────────
    // Teknik sütunlar (#, Arayüz, Bayrak, TTL, Boyut) '.kolon-detay' sınıflı.
    // Basit modda gizlenir; küçük işletme için sade görünüm.
    function kolonGorunurlukUygula() {
        document.querySelectorAll('#gorunum-trafik .kolon-detay').forEach(el => {
            el.classList.toggle('hidden', !detayli);
        });
    }

    function gorunumModuAyarla(yeniDetayli) {
        detayli = !!yeniDetayli;
        const aktif = 'px-3 py-1.5 transition-colors bg-birincil text-white';
        const pasif = 'px-3 py-1.5 transition-colors bg-white text-metin-ikincil hover:bg-slate-50';
        if (btnGorunumBasit) btnGorunumBasit.className = detayli ? pasif : aktif;
        if (btnGorunumDetayli) btnGorunumDetayli.className = detayli ? aktif : pasif;
        kolonGorunurlukUygula();
    }

    // ── Çizim + sayfalama ──────────────────────────────────────
    function ciz(kayitlar) {
        if (!tblGovde) return;
        const offset = (sayfa - 1) * limit;
        const fragment = document.createDocumentFragment();
        kayitlar.forEach((k, i) => fragment.appendChild(paketSatiri(k, offset + i + 1)));
        tblGovde.innerHTML = '';
        tblGovde.appendChild(fragment);
        if (bosMesaj) bosMesaj.classList.toggle('hidden', kayitlar.length > 0);
        kolonGorunurlukUygula();   // yeni satırlara da basit/detaylı uygula
    }

    function durumGuncelle() {
        if (!canliIkon || !durumMetniEl) return;
        const aktifCanli = canli && sayfa === 1;
        canliIkon.className = 'size-2.5 rounded-full ' +
            (aktifCanli ? 'bg-durum-basarili animasyon-nabiz-yavas shadow-parlama-basarili'
                        : (canli ? 'bg-durum-uyari' : 'bg-slate-400'));
        durumMetniEl.textContent = aktifCanli ? 'Canlı akış'
            : (canli ? 'Sayfa görünümü' : 'Duraklatıldı');
    }

    function sayfalamaGuncelle() {
        const filtreli = filtreVarMi();
        const sayfaSayisi = Math.max(1, Math.ceil(toplam / limit));
        if (!filtreli) sayfa = 1;                       // filtresizken hep ilk sayfa
        else if (sayfa > sayfaSayisi) sayfa = sayfaSayisi;

        // Sayfalama navigasyonu YALNIZCA filtre açıkken görünür.
        [btnSayfaIlk, btnSayfaOnceki, btnSayfaSonraki, btnSayfaSon, trafikSayfaMetni].forEach(el => {
            if (el) el.classList.toggle('hidden', !filtreli);
        });

        if (filtreli) {
            if (trafikToplamMetni) trafikToplamMetni.textContent = `${toplam.toLocaleString('tr-TR')} kayıt`;
            if (trafikSayfaMetni) trafikSayfaMetni.textContent = `${sayfa} / ${sayfaSayisi}`;
            if (filtreSayac) filtreSayac.textContent = `${toplam.toLocaleString('tr-TR')} eşleşen`;
            if (sayacEl) sayacEl.textContent = `${toplam.toLocaleString('tr-TR')} kayıt`;
        } else {
            // Filtre yok → sınırlı canlı görünüm (sayfasız)
            if (trafikToplamMetni) trafikToplamMetni.textContent = `Canlı — son ${limit} kayıt`;
            if (filtreSayac) filtreSayac.textContent = '';
            if (sayacEl) sayacEl.textContent = 'Canlı';
        }

        if (btnSayfaIlk) btnSayfaIlk.disabled = sayfa <= 1;
        if (btnSayfaOnceki) btnSayfaOnceki.disabled = sayfa <= 1;
        if (btnSayfaSonraki) btnSayfaSonraki.disabled = sayfa >= sayfaSayisi;
        if (btnSayfaSon) btnSayfaSon.disabled = sayfa >= sayfaSayisi;
        durumGuncelle();
    }

    async function yukle() {
        if (yukleniyor) return;
        yukleniyor = true;
        try {
            const yanit = await Oturum.apiIstegi(`/api/trafik?${sorguDizisi()}`);
            if (yanit && yanit.ok) {
                const veri = await yanit.json();
                toplam = veri.toplam || 0;
                ciz(veri.kayitlar || []);
                sayfalamaGuncelle();
            }
        } catch (e) {
            console.error('[trafik] yükleme hatası:', e);
        } finally {
            yukleniyor = false;
        }
    }

    function trafikSekmesiAcikMi() {
        return window.location.hash.replace('#', '') === 'trafik';
    }

    function pollAyarla() {
        if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
        // Otomatik yenileme yalnızca: canlı + sayfa 1 + sekme açık
        if (canli && sayfa === 1 && trafikSekmesiAcikMi()) {
            pollHandle = setInterval(yukle, POLL_MS);
        }
    }

    function filtreDegisti() {
        sayfa = 1;
        rozetGuncelle();
        yukle();
        pollAyarla();
    }

    function sayfayaGit(yeni) {
        const sayfaSayisi = Math.max(1, Math.ceil(toplam / limit));
        sayfa = Math.min(Math.max(1, yeni), sayfaSayisi);
        yukle();
        pollAyarla();   // sayfa>1 → poll durur; sayfa 1 → poll başlar
    }

    // ── Engellenen erişim denemeleri özeti (grafik + liste) ────
    async function engellenenYukle() {
        if (!engellenenGrafik) return;
        try {
            const yanit = await Oturum.apiIstegi('/api/trafik/engellenen');
            if (!yanit || !yanit.ok) return;
            engellenenCiz(await yanit.json());
        } catch (e) { console.error('[trafik] engellenen özeti hatası:', e); }
    }

    function engellenenCiz(veri) {
        const kaynaklar = veri.kaynaklar || [];
        const detaylar = veri.detaylar || [];
        const maxSayi = kaynaklar.reduce((m, k) => Math.max(m, k.sayi || 0), 0) || 1;

        // Grafik: en çok deneyen kaynaklar (yatay CSS çubukları)
        engellenenGrafik.innerHTML = kaynaklar.length
            ? kaynaklar.map(k => {
                const yuzde = Math.max(4, Math.round((k.sayi / maxSayi) * 100));
                const ip = kacisHTML(k.kaynak_ip || '?');
                return `<div class="flex items-center gap-2 text-xs">
                    <span class="w-28 sm:w-36 truncate font-kod text-metin-ikincil" title="${ip}">${ip}</span>
                    <div class="flex-1 bg-slate-100 rounded h-4 overflow-hidden">
                        <div class="bg-durum-kritik h-4 rounded-r" style="width:${yuzde}%"></div>
                    </div>
                    <span class="w-10 text-right font-semibold text-durum-kritik">${k.sayi}</span>
                </div>`;
            }).join('')
            : '<p class="text-xs text-metin-ucuncul py-2">Henüz engellenen erişim denemesi yok. (Bir engelleme kuralı ekleyip trafik akınca burada görünür.)</p>';

        // Detaylı liste: kaynak → engellenen hedef
        engellenenListe.innerHTML = detaylar.length
            ? detaylar.map(d => {
                const ip = kacisHTML(d.kaynak_ip || '?');
                const hedef = kacisHTML(d.hedef || '?');
                return `<div class="flex items-center gap-2 text-xs py-1 border-b border-slate-50">
                    <span class="w-28 sm:w-32 truncate font-kod text-metin-ikincil" title="${ip}">${ip}</span>
                    <span class="material-symbols-outlined text-sm text-metin-ucuncul">arrow_forward</span>
                    <span class="flex-1 truncate font-medium text-durum-kritik" title="${hedef}">${hedef}</span>
                    <span class="font-semibold tabular-nums">${d.sayi}</span>
                    <span class="text-2xs text-metin-ucuncul w-14 text-right">${tarihKisalt(d.son)}</span>
                </div>`;
            }).join('')
            : '<p class="text-2xs text-metin-ucuncul">—</p>';

        if (engellenenToplam) {
            engellenenToplam.textContent = `${(veri.toplam || 0).toLocaleString('tr-TR')} toplam deneme`;
        }
    }

    function engellenenPollAyarla() {
        if (engellenenPollHandle) { clearInterval(engellenenPollHandle); engellenenPollHandle = null; }
        if (engellenenAcik && trafikSekmesiAcikMi()) {
            engellenenPollHandle = setInterval(engellenenYukle, 8000);
        }
    }

    function engellenenAcKapa(ac) {
        engellenenAcik = ac;
        if (engellenenPanel) engellenenPanel.classList.toggle('hidden', !engellenenAcik);
        if (btnEngellenenOk) btnEngellenenOk.textContent = engellenenAcik ? 'expand_less' : 'expand_more';
        if (btnEngellenenOzet) btnEngellenenOzet.classList.toggle('border-durum-kritik', engellenenAcik);
        if (engellenenAcik) engellenenYukle();
        engellenenPollAyarla();
    }

    if (btnEngellenenOzet) {
        btnEngellenenOzet.addEventListener('click', () => engellenenAcKapa(!engellenenAcik));
    }

    // ── Chip kontrolleri ───────────────────────────────────────
    const CHIP_AKTIF = ['bg-birincil', 'text-white', 'border-birincil'];
    const CHIP_PASIF = ['bg-white', 'text-metin-ucuncul', 'border-kenarlik'];

    function chipGorunum(btn, aktif) {
        if (aktif) { btn.classList.add(...CHIP_AKTIF); btn.classList.remove(...CHIP_PASIF); }
        else { btn.classList.remove(...CHIP_AKTIF); btn.classList.add(...CHIP_PASIF); }
    }

    function chipKur(kapsayici, kume, anahtar, geriCagrim) {
        if (!kapsayici) return;
        kapsayici.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', () => {
                const deger = btn.dataset[anahtar];
                if (kume.has(deger)) kume.delete(deger); else kume.add(deger);
                chipGorunum(btn, kume.has(deger));
                geriCagrim();
            });
        });
    }

    chipKur(protoChipler, secilenProtokoller, 'proto', filtreDegisti);
    chipKur(bayrakChipler, secilenBayraklar, 'bayrak', filtreDegisti);

    // ── Filtre input event'leri (metin için debounce) ──────────
    function debounce(fn, ms) {
        let t;
        return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
    }
    const filtreDegistiDebounce = debounce(filtreDegisti, 350);

    [filtreEylem, filtreYonetimGizle].forEach(el => {
        if (el) el.addEventListener('change', filtreDegisti);
    });
    [filtreArama, filtreKaynakIP, filtreHedefIP, filtreSite, filtrePort].forEach(el => {
        if (el) el.addEventListener('input', filtreDegistiDebounce);
    });

    // "Filtreler" düğmesi → kategorize paneli aç/kapa
    if (btnFiltreAc && filtrePanel) {
        btnFiltreAc.addEventListener('click', () => {
            const gizli = filtrePanel.classList.toggle('hidden');   // true = gizlendi
            if (filtreOkIkon) filtreOkIkon.textContent = gizli ? 'expand_more' : 'expand_less';
        });
    }

    if (btnFiltreSifirla) {
        btnFiltreSifirla.addEventListener('click', () => {
            if (filtreEylem) filtreEylem.value = '';
            if (filtreArama) filtreArama.value = '';
            if (filtreYonetimGizle) filtreYonetimGizle.checked = true;   // varsayılan açık
            [filtreKaynakIP, filtreHedefIP, filtreSite, filtrePort].forEach(el => { if (el) el.value = ''; });
            secilenProtokoller.clear();
            secilenBayraklar.clear();
            if (protoChipler) protoChipler.querySelectorAll('button').forEach(b => chipGorunum(b, false));
            if (bayrakChipler) bayrakChipler.querySelectorAll('button').forEach(b => chipGorunum(b, false));
            filtreDegisti();
        });
    }

    // ── Sayfalama butonları ────────────────────────────────────
    if (btnSayfaIlk) btnSayfaIlk.addEventListener('click', () => sayfayaGit(1));
    if (btnSayfaOnceki) btnSayfaOnceki.addEventListener('click', () => sayfayaGit(sayfa - 1));
    if (btnSayfaSonraki) btnSayfaSonraki.addEventListener('click', () => sayfayaGit(sayfa + 1));
    if (btnSayfaSon) btnSayfaSon.addEventListener('click', () => sayfayaGit(Math.ceil(toplam / limit)));
    if (trafikSayfaBoyutu) {
        trafikSayfaBoyutu.addEventListener('change', () => {
            limit = parseInt(trafikSayfaBoyutu.value, 10) || 50;
            sayfa = 1;
            yukle();
            pollAyarla();
        });
    }

    // ── Duraklat / Yenile ──────────────────────────────────────
    if (btnDuraklat) {
        btnDuraklat.addEventListener('click', () => {
            canli = !canli;
            if (btnDuraklatMetin) btnDuraklatMetin.textContent = canli ? 'Duraklat' : 'Devam';
            const ikon = btnDuraklat.querySelector('.material-symbols-outlined');
            if (ikon) ikon.textContent = canli ? 'pause' : 'play_arrow';
            pollAyarla();
            durumGuncelle();
            if (canli) yukle();
        });
    }
    if (btnYenile) btnYenile.addEventListener('click', () => { yukle(); if (engellenenAcik) engellenenYukle(); });
    if (btnGorunumBasit) btnGorunumBasit.addEventListener('click', () => gorunumModuAyarla(false));
    if (btnGorunumDetayli) btnGorunumDetayli.addEventListener('click', () => gorunumModuAyarla(true));

    // Dışa aktar: mevcut filtrelerle en fazla 500 kaydı .json indir
    // (Sistem Logları → "Eski Trafik Loglarını İncele" ile geri yüklenebilir)
    if (btnDisaAktar) {
        btnDisaAktar.addEventListener('click', async () => {
            const p = new URLSearchParams(sorguDizisi());
            p.set('sayfa', '1');
            p.set('limit', '500');
            try {
                const yanit = await Oturum.apiIstegi(`/api/trafik?${p.toString()}`);
                if (!yanit || !yanit.ok) return;
                const veri = await yanit.json();
                const kayitlar = veri.kayitlar || [];
                const blob = new Blob([JSON.stringify(kayitlar, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                const tarih = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
                a.href = url;
                a.download = `blackbarrier-trafik-${tarih}.json`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
            } catch (e) { console.error('[trafik] dışa aktarma hatası:', e); }
        });
    }

    // ── Sekme yaşam döngüsü ────────────────────────────────────
    document.addEventListener('sekmeYuklendi:trafik', () => {
        sayfa = 1;
        kolonGorunurlukUygula();   // başlık sütunlarını da Basit/Detaylı'ya göre ayarla
        yukle();
        pollAyarla();
        if (engellenenAcik) { engellenenYukle(); engellenenPollAyarla(); }
    });

    window.addEventListener('hashchange', () => {
        if (trafikSekmesiAcikMi()) { pollAyarla(); engellenenPollAyarla(); }
        else {
            if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
            if (engellenenPollHandle) { clearInterval(engellenenPollHandle); engellenenPollHandle = null; }
        }
    });

    window.addEventListener('beforeunload', () => {
        if (pollHandle) clearInterval(pollHandle);
        if (engellenenPollHandle) clearInterval(engellenenPollHandle);
    });
});
