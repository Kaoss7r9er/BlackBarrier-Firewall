/**
 * Black Barrier — Yönlendirme / NAT Sekmesi
 * Backend endpoint'leri:
 *   GET    /api/yonlendirme       → tüm yönlendirme kuralları
 *   POST   /api/yonlendirme       → yeni kural ekle (nftables'a otomatik uygulanır)
 *   DELETE /api/yonlendirme/{id}  → kural sil (nftables'tan da kalkar)
 *
 * Tür eşlemeleri (nftables_yonetici.py ile birebir):
 *   dnat       → port forward (dis_arayuz + protokol + dis_port → ic_ip:ic_port)
 *   snat       → kaynak IP rewrite (dis_arayuz + ic_ip)
 *   masquerade → çıkış arayüzü maskelemesi (sadece dis_arayuz)
 */

document.addEventListener('DOMContentLoaded', () => {

    const tblGovde = document.getElementById('tblYonlendirmeGovde');
    const bosMesaj = document.getElementById('yonlendirmeBos');
    const btnEkle = document.getElementById('btnYonlendirmeEkle');
    const modal = document.getElementById('modalYonlendirme');
    const form = document.getElementById('formYonlendirme');
    const btnKapat = document.getElementById('btnYonlendirmeModalKapat');
    const btnIptal = document.getElementById('btnYonlendirmeModalIptal');
    const btnKaydet = document.getElementById('btnYonlendirmeKaydet');
    const hataKutusu = document.getElementById('modalYonlendirmeHata');
    const ynDnatGrup = document.getElementById('ynDnatGrup');
    const ynMasqGrup = document.getElementById('ynMasqGrup');
    const ynSnatGrup = document.getElementById('ynSnatGrup');
    const ynKuralAdi = document.getElementById('ynKuralAdi');
    const ynDisArayuz = document.getElementById('ynDisArayuz');
    const ynProtokol = document.getElementById('ynProtokol');
    const ynDisPort = document.getElementById('ynDisPort');
    const ynIcIp = document.getElementById('ynIcIp');
    const ynIcPort = document.getElementById('ynIcPort');
    const ynSnatIp = document.getElementById('ynSnatIp');
    const ynAciklama = document.getElementById('ynAciklama');
    let _adManuel = false;

    function yazabilir() {
        const bilgi = (window._oturumBilgisi) || Oturum.oturumKontrol();
        return bilgi && (bilgi.rol === 'admin' || bilgi.rol === 'yonetici');
    }

    function seciliSenaryo() {
        return document.querySelector('input[name="ynSenaryo"]:checked')?.value || 'dnat';
    }

    // ═══════════════════════════════════════
    //  SENARYOYA GÖRE ALANLAR + OTO-AD
    // ═══════════════════════════════════════
    function senaryoGuncelle() {
        const t = seciliSenaryo();
        if (ynDnatGrup) ynDnatGrup.classList.toggle('hidden', t !== 'dnat');
        if (ynMasqGrup) ynMasqGrup.classList.toggle('hidden', t !== 'masquerade');
        if (ynSnatGrup) ynSnatGrup.classList.toggle('hidden', t !== 'snat');
        adOneriGuncelle();
    }

    function onerilenAd() {
        const t = seciliSenaryo();
        if (t === 'dnat') {
            const dp = (ynDisPort?.value || '').trim(), ip = (ynIcIp?.value || '').trim();
            return (dp || ip) ? `Port ${dp || '?'} → ${ip || '?'}` : '';
        }
        if (t === 'masquerade') {
            const w = (ynDisArayuz?.value || '').trim();
            return w ? `İnternet paylaşımı (${w})` : 'İnternet paylaşımı';
        }
        if (t === 'snat') {
            const ip = (ynSnatIp?.value || '').trim();
            return ip ? `Kaynak IP → ${ip}` : '';
        }
        return '';
    }
    function adOneriGuncelle() {
        if (_adManuel || !ynKuralAdi) return;
        ynKuralAdi.value = onerilenAd();
    }

    document.querySelectorAll('input[name="ynSenaryo"]').forEach(r => r.addEventListener('change', senaryoGuncelle));
    [ynDisPort, ynIcIp, ynSnatIp, ynDisArayuz].forEach(el => { if (el) el.addEventListener('input', adOneriGuncelle); });
    if (ynKuralAdi) ynKuralAdi.addEventListener('input', () => { _adManuel = ynKuralAdi.value.trim().length > 0; });

    // ═══════════════════════════════════════
    //  MODAL AÇ/KAPA
    // ═══════════════════════════════════════
    function modalAc() {
        if (!modal) return;
        if (form) form.reset();   // radio'lar default'a (dnat) döner
        if (hataKutusu) hataKutusu.classList.add('hidden');
        _adManuel = false;
        if (ynDisArayuz) ynDisArayuz.value = 'enp0s3';   // varsayılan WAN
        senaryoGuncelle();
        modal.classList.remove('hidden');
    }

    function modalKapat() {
        if (!modal) return;
        modal.classList.add('hidden');
        if (form) form.reset();
        if (hataKutusu) hataKutusu.classList.add('hidden');
    }

    if (btnEkle) btnEkle.addEventListener('click', modalAc);
    if (btnKapat) btnKapat.addEventListener('click', modalKapat);
    if (btnIptal) btnIptal.addEventListener('click', modalKapat);
    if (modal) modal.addEventListener('click', (e) => {
        if (e.target === modal) modalKapat();
    });

    // ═══════════════════════════════════════
    //  KAYDET
    // ═══════════════════════════════════════
    function hataGoster(metin) {
        if (!hataKutusu) return;
        hataKutusu.textContent = metin;
        hataKutusu.classList.remove('hidden');
    }

    async function kuralKaydet(e) {
        if (e) e.preventDefault();
        if (!hataKutusu) return;
        hataKutusu.classList.add('hidden');

        const tur = seciliSenaryo();
        const disArayuz = (ynDisArayuz?.value || '').trim();
        const aciklama = (ynAciklama?.value || '').trim();

        if (!disArayuz) return hataGoster('İnternete çıkış (WAN) arayüzü zorunludur.');

        let protokol = 'herhangi';
        let disPort = '', icIp = '', icPort = '';

        if (tur === 'dnat') {
            protokol = ynProtokol?.value || 'tcp';
            disPort = (ynDisPort?.value || '').trim();
            icIp = (ynIcIp?.value || '').trim();
            icPort = (ynIcPort?.value || '').trim();
            if (!disPort) return hataGoster('Port yönlendirme için "Dışarıdan gelen port" zorunludur.');
            if (!icIp) return hataGoster('Port yönlendirme için iç cihaz IP zorunludur.');
        } else if (tur === 'snat') {
            icIp = (ynSnatIp?.value || '').trim();
            if (!icIp) return hataGoster('SNAT için yeni kaynak IP zorunludur.');
        }

        const kuralAdi = (ynKuralAdi?.value || '').trim() || onerilenAd();
        if (!kuralAdi) return hataGoster('Kurala bir ad ver.');

        const govde = {
            kural_adi: kuralAdi,
            tur,
            protokol,
            dis_arayuz: disArayuz || null,
            ic_arayuz: null,
            dis_port: disPort || null,
            ic_ip: icIp || null,
            ic_port: icPort || null,
            aciklama: aciklama || null,
        };

        if (btnKaydet) {
            btnKaydet.disabled = true;
            btnKaydet.innerHTML = '<span class="material-symbols-outlined text-lg animate-spin">progress_activity</span> Kaydediliyor...';
        }

        try {
            const yanit = await Oturum.apiIstegi('/api/yonlendirme', {
                method: 'POST',
                body: JSON.stringify(govde),
            });
            if (yanit && yanit.ok) {
                modalKapat();
                kurallariYukle();
            } else {
                const err = yanit ? await yanit.json() : null;
                hataGoster((err && err.detail) || 'Kayıt başarısız.');
            }
        } catch (hata) {
            console.error("Yönlendirme kaydetme hatası:", hata);
            hataGoster('Bağlantı hatası.');
        } finally {
            if (btnKaydet) {
                btnKaydet.disabled = false;
                btnKaydet.innerHTML = '<span class="material-symbols-outlined text-lg">save</span> Kaydet';
            }
        }
    }

    if (form) form.addEventListener('submit', kuralKaydet);

    // ═══════════════════════════════════════
    //  KURAL LİSTESİ
    // ═══════════════════════════════════════
    const TUR_GORUNUM = {
        dnat: { metin: 'DNAT', cls: 'bg-blue-50 text-birincil' },
        snat: { metin: 'SNAT', cls: 'bg-purple-50 text-purple-700' },
        masquerade: { metin: 'Masquerade', cls: 'bg-green-50 text-durum-basarili' },
    };

    async function kurallariYukle() {
        if (!tblGovde) return;
        try {
            const yanit = await Oturum.apiIstegi('/api/yonlendirme');
            if (!yanit || !yanit.ok) return;
            const kurallar = await yanit.json();
            tblGovde.innerHTML = '';

            if (bosMesaj) bosMesaj.style.display = kurallar.length === 0 ? '' : 'none';

            const yazma = yazabilir();
            if (btnEkle) btnEkle.style.display = yazma ? '' : 'none';

            kurallar.forEach(k => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-slate-50 transition-colors text-xs';

                const turBilgi = TUR_GORUNUM[k.tur] || { metin: k.tur, cls: 'bg-slate-100 text-metin-ikincil' };
                const turBadge = `<span class="px-2 py-0.5 ${turBilgi.cls} rounded-full font-medium">${turBilgi.metin}</span>`;
                const protokol = (k.protokol || 'herhangi').toUpperCase();

                let disBilgi = `<span class="font-kod">${k.dis_arayuz || '—'}</span>`;
                if (k.dis_port) disBilgi += ` <span class="text-metin-ucuncul font-kod">:${k.dis_port}</span>`;

                let icBilgi = '—';
                if (k.ic_ip) {
                    icBilgi = `<span class="font-kod">${k.ic_ip}</span>`;
                    if (k.ic_port) icBilgi += `<span class="text-metin-ucuncul font-kod">:${k.ic_port}</span>`;
                }

                const islemHucresi = yazma
                    ? `<button class="btn-yn-sil p-1.5 rounded hover:bg-red-50 text-metin-ucuncul hover:text-durum-kritik transition-colors" data-id="${k.id}" title="Sil">
                           <span class="material-symbols-outlined text-base">delete</span>
                       </button>`
                    : '<span class="text-metin-ucuncul">—</span>';

                row.innerHTML = `
                    <td class="px-3 py-2.5 font-medium text-metin-birincil">${k.kural_adi || '—'}</td>
                    <td class="px-3 py-2.5">${turBadge}</td>
                    <td class="px-3 py-2.5"><span class="px-1.5 py-0.5 bg-slate-100 text-metin-ikincil rounded text-2xs font-medium">${protokol}</span></td>
                    <td class="px-3 py-2.5">${disBilgi}</td>
                    <td class="px-3 py-2.5">${icBilgi}</td>
                    <td class="px-3 py-2.5 text-right">${islemHucresi}</td>
                `;
                tblGovde.appendChild(row);
            });

            if (yazma) {
                tblGovde.querySelectorAll('.btn-yn-sil').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const id = e.currentTarget.getAttribute('data-id');
                        if (!confirm("Bu yönlendirme kuralını silmek istediğinize emin misiniz?")) return;
                        try {
                            const silYanit = await Oturum.apiIstegi(`/api/yonlendirme/${id}`, { method: 'DELETE' });
                            if (silYanit && silYanit.ok) {
                                kurallariYukle();
                            } else {
                                alert("Silme başarısız.");
                            }
                        } catch (hata) {
                            console.error("Yönlendirme silme hatası:", hata);
                        }
                    });
                });
            }
        } catch (hata) {
            console.error("Yönlendirme kuralları yüklenemedi:", hata);
        }
    }

    document.addEventListener('sekmeYuklendi:yonlendirme', () => {
        kurallariYukle();
    });
});
