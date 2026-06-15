/**
 * Black Barrier — Güvenlik Kuralları
 *
 * Modal davranışı: stil.css'deki .modal-backdrop / .modal-icerik class'ları
 * ile fade + blur geçişi. modal-backdrop'a .acik class'ı eklenince açılır.
 *
 * Backend alan eşlemesi:
 *   eylem:    izin_ver | engelle | reddet
 *   yon:      giris | cikis | ilet
 *   protokol: tcp | udp | icmp | herhangi
 *   hedef_tip: ip | domain   (domain seçilirse backend DNS ile çözer)
 *   hedef_adres: IP veya domain string (backend'de hedef_ip'ye çözülür)
 *   aktif: bool
 *   zaman_baslangic, zaman_bitis: "HH:MM" — boşsa "sürekli aktif"
 */

document.addEventListener('DOMContentLoaded', () => {

    // ── DOM referansları ──────────────────────────────────────
    const modal = document.getElementById('modalKural');
    const form = document.getElementById('formKural');
    const btnEkle = document.getElementById('btnKuralEkle');
    const btnKapat = document.getElementById('btnKuralModalKapat');
    const btnIptal = document.getElementById('btnKuralIptal');
    const btnKaydet = document.getElementById('btnKuralKaydet');
    const hataKutusu = document.getElementById('modalKuralHata');
    const tblKurallarGovde = document.getElementById('tblKurallarGovde');
    const kurallarBos = document.getElementById('kurallarBos');

    // Filtre + araç çubuğu + firewall durum kontrolleri
    const inpAra = document.getElementById('kuralAra');
    const selFiltreYon = document.getElementById('kuralFiltreYon');
    const selFiltreEylem = document.getElementById('kuralFiltreEylem');
    const selFiltreDurum = document.getElementById('kuralFiltreDurum');
    const filtreSayac = document.getElementById('kuralFiltreSayac');
    const btnDisaAktar = document.getElementById('btnKuralDisaAktar');
    const fwDurumNokta = document.getElementById('fwDurumNokta');
    const fwDurumMetin = document.getElementById('fwDurumMetin');

    // Yüklenen kuralların bellek kopyası (client-side filtre için)
    let _tumKurallar = [];
    let _fwAktif = null;
    let _adManuel = false;   // kullanıcı kural adını elle değiştirdi mi (oto-ad önerisi için)

    // Form alanları
    const inpAdi = document.getElementById('kuralAdi');
    const inpAciklama = document.getElementById('kuralAciklama');
    const selYon = document.getElementById('kuralYon');
    const selProtokol = document.getElementById('kuralProtokol');
    const chkAktif = document.getElementById('kuralAktif');
    const lblAktif = document.getElementById('kuralAktifEtiket');
    const inpKaynakIP = document.getElementById('kuralKaynakIP');
    const inpHedefAdres = document.getElementById('kuralHedefAdres');
    const ipucuHedef = document.getElementById('kuralHedefIpucu');
    const inpHedefPort = document.getElementById('kuralHedefPort');
    const divSaatAralik = document.getElementById('kuralSaatAralik');
    const inpZamanBas = document.getElementById('kuralZamanBaslangic');
    const inpZamanBitis = document.getElementById('kuralZamanBitis');
    const inpOncelik = document.getElementById('kuralOncelik');

    function yazabilir() {
        const bilgi = (window._oturumBilgisi) || Oturum.oturumKontrol();
        return bilgi && (bilgi.rol === 'admin' || bilgi.rol === 'yonetici');
    }

    // ═══════════════════════════════════════
    //  MODAL AÇ / KAPA (yumuşak geçiş)
    // ═══════════════════════════════════════
    function modalAc() {
        if (!modal) return;
        formuTemizle();
        // Görünür hale getir
        modal.classList.remove('invisible');
        modal.style.opacity = '1';
        modal.style.visibility = 'visible';
        // Geçiş için bir frame bekleyip .acik ekle (transition tetiklenir)
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                modal.classList.add('acik');
            });
        });
    }

    function modalKapat() {
        if (!modal) return;
        modal.classList.remove('acik');
        // Animasyon bitince invisible yap (pointer event yutmasın)
        setTimeout(() => {
            modal.style.opacity = '';
            modal.style.visibility = '';
            modal.classList.add('invisible');
        }, 350);
    }

    function formuTemizle() {
        if (form) form.reset();
        if (chkAktif) chkAktif.checked = true;
        _adManuel = false;   // yeni kuralda oto-ad önerisi tekrar açık
        guncelleAktifEtiket();
        guncelleHedefEtiket();
        guncelleZamanlamaGorunum();
        if (hataKutusu) hataKutusu.classList.add('hidden');
    }

    if (btnEkle) btnEkle.addEventListener('click', modalAc);
    if (btnKapat) btnKapat.addEventListener('click', modalKapat);
    if (btnIptal) btnIptal.addEventListener('click', modalKapat);
    if (modal) modal.addEventListener('click', (e) => {
        if (e.target === modal) modalKapat();
    });
    // ESC ile kapat
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal && modal.classList.contains('acik')) {
            modalKapat();
        }
    });

    // ═══════════════════════════════════════
    //  DİNAMİK UI: aktif etiketi, hedef tip etiketi, zaman aralığı
    // ═══════════════════════════════════════
    function guncelleAktifEtiket() {
        if (!chkAktif || !lblAktif) return;
        lblAktif.textContent = chkAktif.checked ? 'Aktif' : 'Pasif';
    }
    if (chkAktif) chkAktif.addEventListener('change', guncelleAktifEtiket);

    function seciliEylem() {
        return document.querySelector('input[name="eylem"]:checked')?.value || 'engelle';
    }
    function seciliHedefTip() {
        return document.querySelector('input[name="hedefTip"]:checked')?.value || 'domain';
    }

    function guncelleHedefEtiket() {
        if (!inpHedefAdres) return;
        if (seciliHedefTip() === 'domain') {
            inpHedefAdres.placeholder = 'örn. youtube.com';
            if (ipucuHedef) ipucuHedef.textContent =
                'Engellemek/izin vermek istediğin web sitesinin adını yaz — alt alan adları (www, m. gibi) da kapsanır.';
        } else {
            inpHedefAdres.placeholder = 'örn. 192.168.1.50';
            if (ipucuHedef) ipucuHedef.textContent =
                'Bir IP adresi veya ağ (CIDR) yaz, örn. 192.168.1.50 ya da 192.168.1.0/24.';
        }
    }

    // Oto-ad önerisi: kullanıcı adı elle değiştirmediyse hedef+eyleme göre öner.
    function onerilenAdGuncelle() {
        if (_adManuel || !inpAdi) return;
        const hedef = (inpHedefAdres?.value || '').trim();
        if (!hedef) { inpAdi.value = ''; return; }
        inpAdi.value = `${hedef} ${seciliEylem() === 'engelle' ? 'engeli' : 'izni'}`;
    }

    document.querySelectorAll('input[name="hedefTip"]').forEach(r => {
        r.addEventListener('change', () => { guncelleHedefEtiket(); onerilenAdGuncelle(); });
    });
    document.querySelectorAll('input[name="eylem"]').forEach(r => {
        r.addEventListener('change', onerilenAdGuncelle);
    });
    if (inpHedefAdres) inpHedefAdres.addEventListener('input', onerilenAdGuncelle);
    if (inpAdi) inpAdi.addEventListener('input', () => { _adManuel = inpAdi.value.trim().length > 0; });

    function guncelleZamanlamaGorunum() {
        if (!divSaatAralik) return;
        const tip = document.querySelector('input[name="zamanlamaTipi"]:checked')?.value || 'surekli';
        if (tip === 'aralik') {
            divSaatAralik.classList.remove('hidden');
        } else {
            divSaatAralik.classList.add('hidden');
            if (inpZamanBas) inpZamanBas.value = '';
            if (inpZamanBitis) inpZamanBitis.value = '';
        }
    }
    document.querySelectorAll('input[name="zamanlamaTipi"]').forEach(r => {
        r.addEventListener('change', guncelleZamanlamaGorunum);
    });

    // ═══════════════════════════════════════
    //  HATA / KAYDET
    // ═══════════════════════════════════════
    function hataGoster(metin) {
        if (!hataKutusu) return;
        hataKutusu.textContent = metin;
        hataKutusu.classList.remove('hidden');
    }

    async function kuralKaydet(e) {
        if (e) e.preventDefault();
        if (hataKutusu) hataKutusu.classList.add('hidden');

        const hedefTip = seciliHedefTip();
        const zamanlamaTipi = document.querySelector('input[name="zamanlamaTipi"]:checked')?.value || 'surekli';
        const hedefAdres = inpHedefAdres?.value.trim() || '';
        const kaynakIP = inpKaynakIP?.value.trim() || '';

        // Yeni başlayan güvenliği: hedef de kaynak da boşsa kural TÜM trafiğe uyar
        // (engelle ise herkesi keser). En az bir hedef belirtmesini iste.
        if (!hedefAdres && !kaynakIP) {
            return hataGoster('Neyi engelley/izin vereceğini yaz (örn. youtube.com veya bir IP). '
                + 'Kaynağa göre kural için Gelişmiş ayarlardan Kaynak IP gir.');
        }

        const ad = (inpAdi?.value.trim()) || (hedefAdres
            ? `${hedefAdres} ${seciliEylem() === 'engelle' ? 'engeli' : 'izni'}`
            : '');
        if (!ad) return hataGoster('Kurala bir ad ver.');

        const govde = {
            kural_adi: ad,
            yon: selYon?.value || 'her',
            protokol: selProtokol?.value || 'herhangi',
            eylem: seciliEylem(),
            aktif: !!chkAktif?.checked,
            kaynak_ip: kaynakIP || null,
            hedef_tip: hedefTip,
            hedef_adres: hedefAdres || null,
            hedef_port: inpHedefPort?.value.trim() || null,
            kaynak_port: null,
            oncelik: (() => {
                const v = parseInt(inpOncelik?.value || '', 10);
                return Number.isFinite(v) && v >= 1 && v <= 999 ? v : 100;
            })(),
            zaman_baslangic: null,
            zaman_bitis: null,
            aciklama: inpAciklama?.value.trim() || null,
        };

        if (zamanlamaTipi === 'aralik') {
            const bas = inpZamanBas?.value.trim() || '';
            const bitis = inpZamanBitis?.value.trim() || '';
            if (!bas || !bitis) {
                return hataGoster('Saat aralığı seçildi — başlangıç ve bitiş saatleri zorunlu.');
            }
            govde.zaman_baslangic = bas;
            govde.zaman_bitis = bitis;
        }

        if (btnKaydet) {
            btnKaydet.disabled = true;
            btnKaydet.innerHTML = '<span class="material-symbols-outlined text-base animate-spin">progress_activity</span> Kaydediliyor...';
        }

        try {
            const yanit = await Oturum.apiIstegi('/api/kurallar', {
                method: 'POST',
                body: JSON.stringify(govde)
            });

            if (yanit && yanit.ok) {
                const veri = await yanit.json();
                modalKapat();
                kurallariYukle();
                // Domain çözülürse kullanıcıya bilgi ver
                if (veri.cozulmus_ip) {
                    console.log(`[kurallar] Domain çözüldü: ${govde.hedef_adres} → ${veri.cozulmus_ip}`);
                }
            } else {
                const err = yanit ? await yanit.json() : null;
                hataGoster((err && err.detail) || 'Kural kaydedilemedi.');
            }
        } catch (e2) {
            console.error("Kural kaydetme hatası:", e2);
            hataGoster('Bağlantı hatası.');
        } finally {
            if (btnKaydet) {
                btnKaydet.disabled = false;
                btnKaydet.innerHTML = '<span class="material-symbols-outlined text-base">save</span> Kaydet';
            }
        }
    }

    if (btnKaydet) btnKaydet.addEventListener('click', kuralKaydet);
    if (form) form.addEventListener('submit', kuralKaydet);

    // ═══════════════════════════════════════
    //  KURAL LİSTESİ
    // ═══════════════════════════════════════
    const EYLEM_GORUNUM = {
        'izin_ver': { metin: 'İzin', cls: 'bg-green-50 text-durum-basarili' },
        'engelle':  { metin: 'Engelle', cls: 'bg-red-50 text-durum-kritik' },
        'reddet':   { metin: 'Reddet', cls: 'bg-orange-50 text-durum-uyari' }
    };
    const YON_GORUNUM = {
        'her':   '✶ Her yön',
        'giris': '↓ Gelen',
        'cikis': '↑ Giden',
        'ilet':  '↔ İlet'
    };

    // DB'den kuralları çek, belleğe al, filtreleyip çiz.
    async function kurallariYukle() {
        if (!tblKurallarGovde) return;
        try {
            const yanit = await Oturum.apiIstegi('/api/kurallar');
            if (yanit && yanit.ok) {
                _tumKurallar = await yanit.json();
                filtreVeCiz();
            }
        } catch (e) {
            console.error("Kurallar yüklenemedi:", e);
        }
    }

    // Aktif filtrelere göre _tumKurallar'ı süzer.
    function filtrelenmis() {
        const ara = (inpAra?.value || '').trim().toLowerCase();
        const fYon = selFiltreYon?.value || '';
        const fEylem = selFiltreEylem?.value || '';
        const fDurum = selFiltreDurum?.value || '';

        return _tumKurallar.filter(k => {
            if (fYon && (k.yon || '') !== fYon) return false;
            if (fEylem && (k.eylem || '') !== fEylem) return false;
            if (fDurum === 'aktif' && k.aktif === 0) return false;
            if (fDurum === 'pasif' && k.aktif !== 0) return false;
            if (ara) {
                const hav = `${k.kural_adi || ''} ${k.kaynak_ip || ''} ${k.kaynak_port || ''} ${k.hedef_ip || ''} ${k.hedef_domain || ''} ${k.hedef_port || ''} ${k.protokol || ''} ${k.aciklama || ''}`.toLowerCase();
                if (!hav.includes(ara)) return false;
            }
            return true;
        });
    }

    function filtreVeCiz() {
        if (!tblKurallarGovde) return;
        const liste = filtrelenmis();
        const yazma = yazabilir();
        if (btnEkle) btnEkle.style.display = yazma ? '' : 'none';

        tblKurallarGovde.innerHTML = '';
        if (kurallarBos) {
            kurallarBos.style.display = liste.length === 0 ? '' : 'none';
            kurallarBos.textContent = _tumKurallar.length === 0
                ? 'Henüz kural eklenmemiş'
                : 'Filtreyle eşleşen kural yok';
        }
        if (filtreSayac) {
            filtreSayac.textContent = `${liste.length} / ${_tumKurallar.length} kural`;
        }

        liste.forEach((k, index) => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-slate-50 transition-colors text-xs';

            const eylem = EYLEM_GORUNUM[k.eylem] || { metin: k.eylem, cls: 'bg-slate-100 text-metin-ikincil' };
            const eylemBadge = `<span class="px-2 py-0.5 ${eylem.cls} rounded-full font-medium">${eylem.metin}</span>`;
            const yonMetin = YON_GORUNUM[k.yon] || k.yon;
            const protokol = (k.protokol || 'herhangi').toUpperCase();
            const aktifMi = k.aktif !== 0;

            let hedefMetin = 'any';
            if (k.hedef_domain) hedefMetin = `${k.hedef_domain} <span class="text-metin-ucuncul">(${k.hedef_ip || '?'})</span>`;
            else if (k.hedef_ip) hedefMetin = k.hedef_ip;
            if (k.hedef_port) hedefMetin += `:${k.hedef_port}`;

            let zamanMetin = '—';
            if (k.zaman_baslangic && k.zaman_bitis) {
                zamanMetin = `${k.zaman_baslangic}–${k.zaman_bitis}`;
            }

            const islemHucresi = yazma ? `
                <div class="flex items-center justify-end gap-2">
                    <label class="relative inline-flex items-center cursor-pointer" title="${aktifMi ? 'Aktif — kapatmak için tıkla (silmez)' : 'Pasif — açmak için tıkla'}">
                        <input type="checkbox" class="sr-only peer kural-toggle-switch" data-id="${k.id}" ${aktifMi ? 'checked' : ''}>
                        <div class="w-9 h-5 bg-slate-300 peer-checked:bg-durum-basarili rounded-full relative transition-colors after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-transform peer-checked:after:translate-x-4"></div>
                    </label>
                    <button class="btn-kural-sil p-1.5 rounded hover:bg-red-50 text-metin-ucuncul hover:text-durum-kritik transition-colors" data-id="${k.id}" title="Kuralı kalıcı sil">
                        <span class="material-symbols-outlined text-base">delete</span>
                    </button>
                </div>` : '<span class="text-metin-ucuncul">—</span>';

            row.innerHTML = `
                <td class="px-3 py-2 text-metin-ucuncul font-kod">${index + 1}</td>
                <td class="px-3 py-2"><span class="w-2 h-2 rounded-full ${aktifMi ? 'bg-durum-basarili' : 'bg-metin-ucuncul'} inline-block"></span></td>
                <td class="px-3 py-2">${eylemBadge}</td>
                <td class="px-3 py-2 text-metin-ikincil">${yonMetin}</td>
                <td class="px-3 py-2 font-kod">${k.kaynak_ip || 'any'}${k.kaynak_port ? ':' + k.kaynak_port : ''}</td>
                <td class="px-3 py-2 font-kod">${hedefMetin}</td>
                <td class="px-3 py-2"><span class="px-1.5 py-0.5 bg-slate-100 text-metin-ikincil rounded text-2xs font-medium">${protokol}</span></td>
                <td class="px-3 py-2 text-metin-ucuncul font-kod">${zamanMetin}</td>
                <td class="px-3 py-2 text-metin-ikincil max-w-[180px] truncate" title="${k.kural_adi || ''}">${k.kural_adi || '—'}</td>
                <td class="px-3 py-2 text-right">${islemHucresi}</td>
            `;
            tblKurallarGovde.appendChild(row);
        });

        if (!yazma) return;

        // Aç/kapa anahtarı — SADECE aktif/pasif yapar, kuralı SİLMEZ.
        document.querySelectorAll('.kural-toggle-switch').forEach(sw => {
            sw.addEventListener('change', async (e) => {
                const id = e.currentTarget.getAttribute('data-id');
                const yeniAktif = e.currentTarget.checked;
                try {
                    const yanit = await Oturum.apiIstegi(`/api/kurallar/${id}/durum?aktif=${yeniAktif}`, { method: 'PATCH' });
                    if (!yanit || !yanit.ok) throw new Error('durum güncellenemedi');
                    kurallariYukle();
                } catch (err) {
                    console.error(err);
                    kurallariYukle();   // hatada gerçek durumu geri yükle
                }
            });
        });

        document.querySelectorAll('.btn-kural-sil').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const id = e.currentTarget.getAttribute('data-id');
                if (confirm("Bu kuralı KALICI olarak silmek istediğine emin misin? (Geçici kapatmak için yandaki anahtarı kullan.)")) {
                    try {
                        await Oturum.apiIstegi(`/api/kurallar/${id}`, { method: 'DELETE' });
                        kurallariYukle();
                    } catch (err) { console.error(err); }
                }
            });
        });
    }

    // ── Filtre event'leri ────────────────────────────────────
    if (inpAra) inpAra.addEventListener('input', filtreVeCiz);
    [selFiltreYon, selFiltreEylem, selFiltreDurum].forEach(el => {
        if (el) el.addEventListener('change', filtreVeCiz);
    });

    // ── Dışa aktar (JSON) ────────────────────────────────────
    if (btnDisaAktar) {
        btnDisaAktar.addEventListener('click', () => {
            const veri = JSON.stringify(_tumKurallar, null, 2);
            const blob = new Blob([veri], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            const tarih = new Date().toISOString().slice(0, 10);
            a.href = url;
            a.download = `blackbarrier-kurallar-${tarih}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        });
    }

    // ── Firewall master durum göstergesi (yalnızca bilgi — kapatma kaldırıldı) ──
    function fwDurumGoster() {
        if (!fwDurumNokta || !fwDurumMetin) return;
        if (_fwAktif === null) {
            fwDurumNokta.className = 'size-2.5 rounded-full bg-slate-300';
            fwDurumMetin.textContent = 'Durum…';
            return;
        }
        fwDurumNokta.className = 'size-2.5 rounded-full ' + (_fwAktif ? 'bg-durum-basarili' : 'bg-durum-kritik');
        fwDurumMetin.textContent = _fwAktif ? 'Güvenlik duvarı AÇIK' : 'Güvenlik duvarı KAPALI';
    }

    async function fwDurumYukle() {
        try {
            const yanit = await Oturum.apiIstegi('/api/firewall/durum');
            if (yanit && yanit.ok) {
                const veri = await yanit.json();
                _fwAktif = !!veri.aktif;
            }
        } catch (e) { console.error('Firewall durumu okunamadı:', e); }
        fwDurumGoster();
    }

    document.addEventListener('sekmeYuklendi:kurallar', () => {
        kurallariYukle();
        fwDurumYukle();
    });
});
