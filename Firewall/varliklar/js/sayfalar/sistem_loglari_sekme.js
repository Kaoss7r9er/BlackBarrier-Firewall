/**
 * Black Barrier — Sistem Logları Sekmesi (Modüler)
 * Sadece "Sistem Logları" sekmesine girildiğinde çalışır.
 */

document.addEventListener('DOMContentLoaded', () => {
    
    const tblSistemLoglariGovde = document.getElementById('tblSistemLoglariGovde');
    const btnSistemLogYenile = document.getElementById('btnSistemLogYenile');
    const selSistemLogFiltre = document.getElementById('selSistemLogFiltre');

    // Şüpheli IP grafiği + listesi
    const supheliGrafik = document.getElementById('supheliGrafik');
    const supheliListe = document.getElementById('supheliListe');
    const supheliToplam = document.getElementById('supheliToplam');

    function kacis(s) {
        return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    }
    function zamanKisa(iso) {
        if (!iso) return '—';
        const t = new Date(iso);
        if (isNaN(t.getTime())) return '—';
        return t.toLocaleString('tr-TR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    }

    async function supheliIpleriYukle() {
        if (!supheliGrafik) return;
        try {
            const yanit = await Oturum.apiIstegi('/api/guvenlik/supheli-ipler');
            if (!yanit || !yanit.ok) return;
            const veri = await yanit.json();
            const ipler = veri.ipler || [];
            const maxSkor = ipler.reduce((m, x) => Math.max(m, x.skor || 0), 0) || 1;

            // Minimal/modern yatay çubuk grafik: tek kırmızı vurgu, genişlik+opaklık şiddeti gösterir
            supheliGrafik.innerHTML = ipler.length
                ? ipler.map(x => {
                    const oran = x.skor / maxSkor;
                    const yuzde = Math.max(6, Math.round(oran * 100));
                    const opaklik = (0.45 + 0.55 * oran).toFixed(2);
                    const ip = kacis(x.ip);
                    return `<div class="flex items-center gap-3">
                        <span class="w-32 sm:w-40 shrink-0 truncate font-kod text-xs text-metin-ikincil" title="${ip}">${ip}</span>
                        <div class="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                            <div class="bg-durum-kritik h-2 rounded-full transition-all duration-500" style="width:${yuzde}%;opacity:${opaklik}"></div>
                        </div>
                        <span class="w-8 text-right text-xs font-semibold text-metin-birincil tabular-nums">${x.skor}</span>
                    </div>`;
                }).join('')
                : '<p class="text-xs text-metin-ucuncul py-2">Şüpheli aktivite yok. (Başarısız panel girişi veya engellenen erişim olunca burada görünür.)</p>';

            // Detaylı liste: IP · neden · son görülme
            if (supheliListe) {
                supheliListe.classList.toggle('hidden', ipler.length === 0);
                supheliListe.innerHTML = ipler.map(x => `
                    <div class="flex items-center justify-between gap-3 py-1.5 text-xs">
                        <span class="font-kod text-metin-birincil truncate w-32 sm:w-40 shrink-0" title="${kacis(x.ip)}">${kacis(x.ip)}</span>
                        <span class="flex-1 text-metin-ucuncul truncate" title="${kacis(x.sebep)}">${kacis(x.sebep)}</span>
                        <span class="text-2xs text-metin-ucuncul whitespace-nowrap">${zamanKisa(x.son)}</span>
                    </div>`).join('');
            }

            if (supheliToplam) supheliToplam.textContent = `${(veri.toplam || 0)} şüpheli adres`;
        } catch (e) {
            console.error('Şüpheli IP listesi çekilemedi:', e);
        }
    }

    async function tumSistemLoglariniYukle() {
        if (!tblSistemLoglariGovde) return;

        try {
            let url = '/api/sistem-loglari?limit=200';
            if (selSistemLogFiltre && selSistemLogFiltre.value) {
                url += `&olay_turu=${selSistemLogFiltre.value}`;
            }

            const yanit = await Oturum.apiIstegi(url);
            if (yanit && yanit.ok) {
                const loglar = await yanit.json();
                tblSistemLoglariGovde.innerHTML = '';

                if (loglar.length === 0) {
                    tblSistemLoglariGovde.innerHTML = `
                        <tr>
                            <td colspan="3" class="py-4 text-center text-slate-500 font-kod text-xs uppercase">
                                Log kaydı bulunamadı.
                            </td>
                        </tr>
                    `;
                    return;
                }

                loglar.forEach(log => {
                    let ikon = 'info';
                    let renkCls = 'text-birincil';
                    
                    if (log.olay_turu === 'yeniden_baslatma') {
                        ikon = 'restart_alt';
                        renkCls = 'text-durum-uyari';
                    } else if (log.olay_turu === 'hata') {
                        ikon = 'error';
                        renkCls = 'text-durum-kritik';
                    } else if (log.olay_turu === 'durma') {
                        ikon = 'stop_circle';
                        renkCls = 'text-slate-600';
                    } else if (log.olay_turu === 'baslangic') {
                        ikon = 'play_circle';
                        renkCls = 'text-durum-basarili';
                    }

                    const tarih = new Date(log.zaman);
                    const saatFormati = tarih.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
                    const tarihFormati = tarih.toLocaleDateString('tr-TR', { day: '2-digit', month: '2-digit', year: 'numeric' });

                    const row = document.createElement('tr');
                    row.className = 'border-b border-slate-100 hover:bg-slate-50 transition-colors';
                    row.innerHTML = `
                        <td class="py-3 px-4 text-xs">
                            <div class="font-bold text-slate-800">${tarihFormati}</div>
                            <div class="text-slate-500">${saatFormati}</div>
                        </td>
                        <td class="py-3 px-4">
                            <div class="flex items-center gap-1 ${renkCls}">
                                <span class="material-symbols-outlined text-[16px]">${ikon}</span>
                                <span class="text-[10px] font-bold uppercase tracking-wider">${log.olay_turu.replace('_', ' ')}</span>
                            </div>
                        </td>
                        <td class="py-3 px-4 text-slate-700 leading-snug">
                            ${log.aciklama}
                        </td>
                    `;
                    tblSistemLoglariGovde.appendChild(row);
                });
            }
        } catch (hata) {
            console.error("Detaylı loglar çekilemedi:", hata);
        }
    }

    // ── Eski trafik logu içeri aktar + gelişmiş filtre + sayfalama + VirusTotal ──
    const btnLogIceriAktar = document.getElementById('btnLogIceriAktar');
    const logDosyaInput = document.getElementById('logDosyaInput');
    const logIceriDurum = document.getElementById('logIceriDurum');
    const iceriLogBos = document.getElementById('iceriLogBos');
    const iceriLogIcerik = document.getElementById('iceriLogIcerik');
    const tblIceriLogGovde = document.getElementById('tblIceriLogGovde');
    const iceriEslesmeYok = document.getElementById('iceriEslesmeYok');
    // Filtre kontrolleri
    const iceriAra = document.getElementById('iceriAra');
    const iceriEylem = document.getElementById('iceriEylem');
    const iceriGelismisAc = document.getElementById('iceriGelismisAc');
    const iceriGelismisPanel = document.getElementById('iceriGelismisPanel');
    const iceriGelismisOk = document.getElementById('iceriGelismisOk');
    const iceriGelismisRozet = document.getElementById('iceriGelismisRozet');
    const btnIceriSifirla = document.getElementById('btnIceriSifirla');
    const iceriSayac = document.getElementById('iceriSayac');
    const iceriKaynak = document.getElementById('iceriKaynak');
    const iceriHedef = document.getElementById('iceriHedef');
    const iceriSite = document.getElementById('iceriSite');
    const iceriPort = document.getElementById('iceriPort');
    const iceriProtoChipler = document.getElementById('iceriProtoChipler');
    const iceriBayrakChipler = document.getElementById('iceriBayrakChipler');
    const iceriZamanBas = document.getElementById('iceriZamanBas');
    const iceriZamanBitis = document.getElementById('iceriZamanBitis');
    // Sayfalama
    const iceriSayfaBoyutu = document.getElementById('iceriSayfaBoyutu');
    const iceriSayfaMetni = document.getElementById('iceriSayfaMetni');
    const btnIceriIlk = document.getElementById('btnIceriIlk');
    const btnIceriOnceki = document.getElementById('btnIceriOnceki');
    const btnIceriSonraki = document.getElementById('btnIceriSonraki');
    const btnIceriSon = document.getElementById('btnIceriSon');

    let _iceriKayitlar = [];
    let _iceriSayfa = 1;
    let _iceriLimit = 50;
    const secilenIceriProto = new Set();
    const secilenIceriBayrak = new Set();

    const EYLEM_ROZET = {
        'izin_ver': { metin: 'İzin', cls: 'bg-green-50 text-durum-basarili' },
        'engelle':  { metin: 'Engellendi', cls: 'bg-red-50 text-durum-kritik' },
        'reddet':   { metin: 'Reddedildi', cls: 'bg-orange-50 text-durum-uyari' },
    };

    // İlgili hedefi (domain öncelikli, yoksa IP) VirusTotal analiz sayfasında aç.
    function virustotalUrl(k) {
        const domain = (k.info || k.hedef_domain || '').trim();
        const ip = (k.hedef_ip || '').trim();
        if (domain) return `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`;
        if (ip) return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`;
        return null;
    }

    function iceriSatir(k) {
        const ey = EYLEM_ROZET[k.eylem] || { metin: k.eylem || '—', cls: 'bg-slate-100 text-metin-ikincil' };
        const kaynak = kacis(k.kaynak_ip || '—') + (k.kaynak_port ? ':' + kacis(k.kaynak_port) : '');
        const hedef = kacis(k.hedef_ip || '—') + (k.hedef_port ? ':' + kacis(k.hedef_port) : '');
        const site = (k.info || k.hedef_domain || '').trim();
        const vtUrl = virustotalUrl(k);
        const vtBtn = vtUrl
            ? `<a href="${vtUrl}" target="_blank" rel="noopener" class="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-blue-200 text-blue-600 hover:bg-blue-50 text-2xs font-semibold transition-colors" title="VirusTotal'de tara: ${kacis(site || k.hedef_ip || '')}">
                   <span class="material-symbols-outlined text-sm">travel_explore</span> VirusTotal</a>`
            : '<span class="text-2xs text-metin-ucuncul">—</span>';
        return `<tr class="hover:bg-slate-50 transition-colors">
            <td class="px-4 py-2 text-xs text-metin-ucuncul whitespace-nowrap">${zamanKisa(k.zaman)}</td>
            <td class="px-4 py-2 text-xs font-kod">${kaynak}</td>
            <td class="px-4 py-2 text-xs font-kod">${hedef}</td>
            <td class="px-4 py-2 text-xs ${site ? 'text-birincil font-medium' : 'text-metin-ucuncul'}">${site ? kacis(site) : '—'}</td>
            <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-2xs font-semibold ${ey.cls}">${kacis(ey.metin)}</span></td>
            <td class="px-4 py-2 text-center">${vtBtn}</td>
        </tr>`;
    }

    // Tüm filtreleri uygula → eşleşen kayıtlar
    function iceriFiltrele() {
        const ara = (iceriAra && iceriAra.value || '').trim().toLowerCase();
        const eylem = iceriEylem && iceriEylem.value || '';
        const kaynak = (iceriKaynak && iceriKaynak.value || '').trim();
        const hedef = (iceriHedef && iceriHedef.value || '').trim();
        const site = (iceriSite && iceriSite.value || '').trim().toLowerCase();
        const port = (iceriPort && iceriPort.value || '').trim();
        const basT = (iceriZamanBas && iceriZamanBas.value) ? new Date(iceriZamanBas.value).getTime() : null;
        const bitT = (iceriZamanBitis && iceriZamanBitis.value) ? new Date(iceriZamanBitis.value).getTime() : null;

        return _iceriKayitlar.filter(k => {
            if (eylem && (k.eylem || '') !== eylem) return false;
            if (kaynak && !String(k.kaynak_ip || '').includes(kaynak)) return false;
            if (hedef && !String(k.hedef_ip || '').includes(hedef)) return false;
            if (site && !String(k.info || k.hedef_domain || '').toLowerCase().includes(site)) return false;
            if (port) {
                if (String(k.kaynak_port || '') !== port && String(k.hedef_port || '') !== port) return false;
            }
            if (secilenIceriProto.size) {
                const pr = String(k.protokol || '').toLowerCase();
                const grup = (pr === 'tcp' || pr === 'udp' || pr === 'icmp') ? pr : 'diger';
                if (!secilenIceriProto.has(grup)) return false;
            }
            if (secilenIceriBayrak.size) {
                const f = String(k.tcp_bayraklari || '');
                for (const b of secilenIceriBayrak) if (!f.includes(b)) return false;
            }
            if (basT !== null || bitT !== null) {
                const t = k.zaman ? new Date(k.zaman).getTime() : NaN;
                if (isNaN(t)) return false;
                if (basT !== null && t < basT) return false;
                if (bitT !== null && t > bitT) return false;
            }
            if (ara) {
                const hav = `${k.kaynak_ip || ''} ${k.kaynak_port || ''} ${k.hedef_ip || ''} ${k.hedef_port || ''} ${k.info || k.hedef_domain || ''} ${k.protokol || ''} ${k.eylem || ''} ${k.tcp_bayraklari || ''}`.toLowerCase();
                if (!hav.includes(ara)) return false;
            }
            return true;
        });
    }

    function iceriGelismisRozetGuncelle() {
        if (!iceriGelismisRozet) return;
        let n = 0;
        if ((iceriKaynak && iceriKaynak.value || '').trim()) n++;
        if ((iceriHedef && iceriHedef.value || '').trim()) n++;
        if ((iceriSite && iceriSite.value || '').trim()) n++;
        if ((iceriPort && iceriPort.value || '').trim()) n++;
        if (secilenIceriProto.size) n++;
        if (secilenIceriBayrak.size) n++;
        if (iceriZamanBas && iceriZamanBas.value) n++;
        if (iceriZamanBitis && iceriZamanBitis.value) n++;
        iceriGelismisRozet.textContent = String(n);
        iceriGelismisRozet.classList.toggle('hidden', n === 0);
    }

    function iceriCiz() {
        if (!tblIceriLogGovde) return;
        const filtreli = iceriFiltrele();
        const toplam = filtreli.length;
        const sayfaSayisi = Math.max(1, Math.ceil(toplam / _iceriLimit));
        if (_iceriSayfa > sayfaSayisi) _iceriSayfa = sayfaSayisi;
        if (_iceriSayfa < 1) _iceriSayfa = 1;
        const bas = (_iceriSayfa - 1) * _iceriLimit;
        const dilim = filtreli.slice(bas, bas + _iceriLimit);

        tblIceriLogGovde.innerHTML = dilim.map(iceriSatir).join('');
        if (iceriEslesmeYok) iceriEslesmeYok.classList.toggle('hidden', dilim.length > 0);
        if (iceriSayfaMetni) iceriSayfaMetni.textContent = `${_iceriSayfa} / ${sayfaSayisi}`;
        if (iceriSayac) iceriSayac.textContent = `${toplam.toLocaleString('tr-TR')} / ${_iceriKayitlar.length.toLocaleString('tr-TR')} kayıt`;
        if (btnIceriIlk) btnIceriIlk.disabled = _iceriSayfa <= 1;
        if (btnIceriOnceki) btnIceriOnceki.disabled = _iceriSayfa <= 1;
        if (btnIceriSonraki) btnIceriSonraki.disabled = _iceriSayfa >= sayfaSayisi;
        if (btnIceriSon) btnIceriSon.disabled = _iceriSayfa >= sayfaSayisi;
        iceriGelismisRozetGuncelle();
    }

    function iceriFiltreDegisti() { _iceriSayfa = 1; iceriCiz(); }

    function iceriSayfayaGit(yeni) {
        const sayfaSayisi = Math.max(1, Math.ceil(iceriFiltrele().length / _iceriLimit));
        _iceriSayfa = Math.min(Math.max(1, yeni), sayfaSayisi);
        iceriCiz();
    }

    // Chip kontrolleri
    const ICERI_CHIP_AKTIF = ['bg-birincil', 'text-white', 'border-birincil'];
    const ICERI_CHIP_PASIF = ['bg-white', 'text-metin-ucuncul', 'border-kenarlik'];
    function iceriChipGorunum(btn, aktif) {
        if (aktif) { btn.classList.add(...ICERI_CHIP_AKTIF); btn.classList.remove(...ICERI_CHIP_PASIF); }
        else { btn.classList.remove(...ICERI_CHIP_AKTIF); btn.classList.add(...ICERI_CHIP_PASIF); }
    }
    function iceriChipKur(kapsayici, kume, anahtar) {
        if (!kapsayici) return;
        kapsayici.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', () => {
                const deger = btn.dataset[anahtar];
                if (kume.has(deger)) kume.delete(deger); else kume.add(deger);
                iceriChipGorunum(btn, kume.has(deger));
                iceriFiltreDegisti();
            });
        });
    }
    iceriChipKur(iceriProtoChipler, secilenIceriProto, 'proto');
    iceriChipKur(iceriBayrakChipler, secilenIceriBayrak, 'bayrak');

    function iceriFiltreleriSifirla() {
        if (iceriAra) iceriAra.value = '';
        if (iceriEylem) iceriEylem.value = '';
        [iceriKaynak, iceriHedef, iceriSite, iceriPort, iceriZamanBas, iceriZamanBitis].forEach(el => { if (el) el.value = ''; });
        secilenIceriProto.clear();
        secilenIceriBayrak.clear();
        if (iceriProtoChipler) iceriProtoChipler.querySelectorAll('button').forEach(b => iceriChipGorunum(b, false));
        if (iceriBayrakChipler) iceriBayrakChipler.querySelectorAll('button').forEach(b => iceriChipGorunum(b, false));
    }

    // Filtre event'leri
    [iceriAra, iceriKaynak, iceriHedef, iceriSite, iceriPort].forEach(el => {
        if (el) el.addEventListener('input', iceriFiltreDegisti);
    });
    [iceriEylem, iceriZamanBas, iceriZamanBitis].forEach(el => {
        if (el) el.addEventListener('change', iceriFiltreDegisti);
    });
    if (iceriGelismisAc && iceriGelismisPanel) {
        iceriGelismisAc.addEventListener('click', () => {
            const gizli = iceriGelismisPanel.classList.toggle('hidden');
            if (iceriGelismisOk) iceriGelismisOk.textContent = gizli ? 'expand_more' : 'expand_less';
        });
    }
    if (btnIceriSifirla) {
        btnIceriSifirla.addEventListener('click', () => { iceriFiltreleriSifirla(); iceriFiltreDegisti(); });
    }
    if (iceriSayfaBoyutu) {
        iceriSayfaBoyutu.addEventListener('change', () => {
            _iceriLimit = parseInt(iceriSayfaBoyutu.value, 10) || 50;
            _iceriSayfa = 1;
            iceriCiz();
        });
    }
    if (btnIceriIlk) btnIceriIlk.addEventListener('click', () => iceriSayfayaGit(1));
    if (btnIceriOnceki) btnIceriOnceki.addEventListener('click', () => iceriSayfayaGit(_iceriSayfa - 1));
    if (btnIceriSonraki) btnIceriSonraki.addEventListener('click', () => iceriSayfayaGit(_iceriSayfa + 1));
    if (btnIceriSon) btnIceriSon.addEventListener('click', () => iceriSayfayaGit(Infinity));

    function dosyaIceriAktar(file) {
        const okuyucu = new FileReader();
        okuyucu.onload = (e) => {
            try {
                const veri = JSON.parse(e.target.result);
                const kayitlar = Array.isArray(veri) ? veri
                    : (Array.isArray(veri && veri.kayitlar) ? veri.kayitlar : null);
                if (!kayitlar) {
                    if (logIceriDurum) logIceriDurum.textContent = 'Geçersiz format (JSON dizisi bekleniyor).';
                    return;
                }
                _iceriKayitlar = kayitlar;
                _iceriSayfa = 1;
                iceriFiltreleriSifirla();
                if (iceriLogBos) iceriLogBos.classList.add('hidden');
                if (iceriLogIcerik) iceriLogIcerik.classList.remove('hidden');
                iceriCiz();
                if (logIceriDurum) logIceriDurum.textContent = `${kayitlar.length.toLocaleString('tr-TR')} kayıt yüklendi`;
            } catch (err) {
                if (logIceriDurum) logIceriDurum.textContent = 'Dosya okunamadı (geçerli JSON değil).';
                console.error('Log içe aktarma hatası:', err);
            }
        };
        okuyucu.readAsText(file);
    }

    if (btnLogIceriAktar && logDosyaInput) {
        btnLogIceriAktar.addEventListener('click', () => logDosyaInput.click());
        logDosyaInput.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            if (file) dosyaIceriAktar(file);
            e.target.value = '';   // aynı dosya tekrar seçilebilsin
        });
    }

    // ═══════════════════════════════════════
    //  DOSYA DEĞİŞİKLİKLERİ (File Integrity Monitor)
    // ═══════════════════════════════════════
    const dosyaListe       = document.getElementById('dosyaDegisiklikleriListe');
    const dosyaBosMesaj    = document.getElementById('dosyaDegisiklikleriBos');
    const dosyaToplam      = document.getElementById('dosyaDegisikligiToplam');
    const btnDosyaTara     = document.getElementById('btnDosyaTara');

    const _TUR_STILI = {
        yeni:     { ikon: 'add_circle', metin: 'Yeni',     metinCls: 'text-durum-basarili', bgCls: 'bg-green-50',  rozetCls: 'bg-green-100 text-durum-basarili' },
        degisti:  { ikon: 'edit',       metin: 'Değişti',  metinCls: 'text-durum-uyari',    bgCls: 'bg-orange-50', rozetCls: 'bg-orange-100 text-durum-uyari' },
        silindi:  { ikon: 'delete',     metin: 'Silindi',  metinCls: 'text-durum-kritik',   bgCls: 'bg-red-50',    rozetCls: 'bg-red-100 text-durum-kritik' },
    };

    function _kacisDosya(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function _zamanFmt(z) {
        if (!z) return '—';
        const t = new Date(z);
        if (isNaN(t.getTime())) return _kacisDosya(z);
        return t.toLocaleString('tr-TR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    }

    async function dosyaDegisiklikleriniYukle(tara = true) {
        if (!dosyaListe) return;
        try {
            const yanit = await Oturum.apiIstegi(`/api/dosya-degisiklikleri?limit=50&tara=${tara ? 1 : 0}`);
            if (!yanit || !yanit.ok) return;
            const veri = await yanit.json();
            const liste = veri.degisiklikler || [];

            if (dosyaToplam) dosyaToplam.textContent = liste.length ? `${liste.length} kayıt` : '';
            if (dosyaBosMesaj) dosyaBosMesaj.classList.toggle('hidden', liste.length !== 0);

            dosyaListe.innerHTML = liste.map(k => {
                const st = _TUR_STILI[k.degisim_turu] || _TUR_STILI.degisti;
                return `
                    <div class="flex items-center justify-between gap-2 px-2.5 py-1.5 ${st.bgCls} rounded-lg">
                        <div class="flex items-center gap-2 min-w-0 flex-1">
                            <span class="material-symbols-outlined text-base ${st.metinCls} shrink-0">${st.ikon}</span>
                            <span class="font-kod text-xs text-metin-birincil truncate" title="${_kacisDosya(k.yol)}">${_kacisDosya(k.yol)}</span>
                            <span class="px-1.5 py-0.5 ${st.rozetCls} text-2xs font-semibold rounded shrink-0">${st.metin}</span>
                        </div>
                        <span class="text-2xs font-kod text-metin-ucuncul shrink-0">${_zamanFmt(k.zaman)}</span>
                    </div>`;
            }).join('');
        } catch (hata) {
            console.error('Dosya değişiklikleri yüklenemedi:', hata);
        }
    }

    if (btnDosyaTara) {
        btnDosyaTara.addEventListener('click', () => dosyaDegisiklikleriniYukle(true));
    }

    // ═══════════════════════════════════════
    //  TRAFİK ARŞİVİ (12 saatlik snapshot + sha256)
    // ═══════════════════════════════════════
    const trafikArsivListe    = document.getElementById('trafikArsivListe');
    const trafikArsivBos      = document.getElementById('trafikArsivBos');
    const trafikArsivToplam   = document.getElementById('trafikArsivToplam');
    const btnArsivCalistir    = document.getElementById('btnTrafikArsivCalistir');

    function _byteFmt(b) {
        if (b == null) return '—';
        if (b < 1024) return `${b} B`;
        if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
        return `${(b / (1024 * 1024)).toFixed(2)} MB`;
    }
    function _temelDosyaAdi(yol) {
        if (!yol) return '—';
        const parcalar = String(yol).split(/[/\\]/);
        return parcalar[parcalar.length - 1] || yol;
    }

    async function trafikArsiviYukle() {
        if (!trafikArsivListe) return;
        try {
            const yanit = await Oturum.apiIstegi('/api/trafik/arsiv?limit=50');
            if (!yanit || !yanit.ok) return;
            const veri = await yanit.json();
            const liste = veri.arsivler || [];

            if (trafikArsivToplam) trafikArsivToplam.textContent = liste.length ? `${liste.length} snapshot` : '';
            if (trafikArsivBos) trafikArsivBos.classList.toggle('hidden', liste.length !== 0);

            trafikArsivListe.innerHTML = liste.map(a => {
                const dosya = _kacisDosya(_temelDosyaAdi(a.dosya_yolu));
                const yolTam = _kacisDosya(a.dosya_yolu);
                const ozetKisa = (a.sha256 || '').substring(0, 16);
                const ozetTam = _kacisDosya(a.sha256 || '');
                const zaman = _zamanFmt(a.zaman);
                return `
                    <div class="flex items-start justify-between gap-3 p-3 bg-slate-50 rounded-lg border border-kenarlik">
                        <div class="flex items-start gap-2 min-w-0 flex-1">
                            <span class="material-symbols-outlined text-base text-birincil shrink-0 mt-0.5">description</span>
                            <div class="min-w-0 flex-1">
                                <div class="flex items-center gap-2 flex-wrap">
                                    <span class="font-kod text-xs font-semibold text-metin-birincil truncate" title="${yolTam}">${dosya}</span>
                                    <span class="px-1.5 py-0.5 bg-blue-100 text-blue-700 text-2xs font-semibold rounded">${a.kayit_sayisi} kayıt</span>
                                    <span class="text-2xs text-metin-ucuncul">${_byteFmt(a.boyut_byte)}</span>
                                </div>
                                <div class="flex items-center gap-1.5 mt-1 text-2xs font-kod text-metin-ucuncul" title="${ozetTam}">
                                    <span class="material-symbols-outlined text-xs">tag</span>
                                    <span>sha256:</span>
                                    <span class="text-metin-ikincil">${ozetKisa}…</span>
                                </div>
                            </div>
                        </div>
                        <span class="text-2xs font-kod text-metin-ucuncul shrink-0 whitespace-nowrap">${zaman}</span>
                    </div>`;
            }).join('');
        } catch (hata) {
            console.error('Trafik arşivi yüklenemedi:', hata);
        }
    }

    if (btnArsivCalistir) {
        btnArsivCalistir.addEventListener('click', async () => {
            const eskiHtml = btnArsivCalistir.innerHTML;
            btnArsivCalistir.disabled = true;
            btnArsivCalistir.innerHTML = '<span class="material-symbols-outlined text-base animate-spin">progress_activity</span> Arşivleniyor...';
            try {
                const yanit = await Oturum.apiIstegi('/api/trafik/arsiv/calistir', { method: 'POST' });
                if (yanit && yanit.ok) {
                    const sonuc = await yanit.json();
                    if (!sonuc.yapildi && sonuc.neden) {
                        alert(sonuc.neden);
                    }
                    await trafikArsiviYukle();
                } else {
                    const err = yanit ? await yanit.json() : null;
                    alert((err && err.detail) || 'Arşivleme başarısız.');
                }
            } catch (hata) {
                console.error('Manuel arşivleme hatası:', hata);
                alert('Bağlantı hatası.');
            } finally {
                btnArsivCalistir.disabled = false;
                btnArsivCalistir.innerHTML = eskiHtml;
            }
        });
    }

    if (btnSistemLogYenile) {
        btnSistemLogYenile.addEventListener('click', () => {
            tumSistemLoglariniYukle();
            supheliIpleriYukle();
            dosyaDegisiklikleriniYukle(true);
            trafikArsiviYukle();
        });
    }

    if (selSistemLogFiltre) {
        selSistemLogFiltre.addEventListener('change', tumSistemLoglariniYukle);
    }

    // Yönlendirme motorundan gelen özel event'i dinle
    document.addEventListener('sekmeYuklendi:sistem_loglari_sekme', () => {
        tumSistemLoglariniYukle();
        supheliIpleriYukle();
        dosyaDegisiklikleriniYukle(true);
        trafikArsiviYukle();
    });

});
