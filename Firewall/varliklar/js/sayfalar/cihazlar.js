/**
 * Black Barrier — Bağlı Cihazlar Sekmesi
 *
 * Backend endpoint:
 *   GET /api/baglantili-cihazlar  → DHCP lease + ARP birleştirmesi
 *
 * Özellikler:
 *   - Cihaz listesi (IP, MAC, hostname, kaynak: dhcp/arp/dhcp+arp, son görülme)
 *   - "Hızlı Engelle" butonu → o IP için engelleme kuralı oluşturur (admin/yonetici)
 *   - Yenile butonu + auto-refresh (sekme açıkken her 30sn)
 */

document.addEventListener('DOMContentLoaded', () => {

    const tblGovde = document.getElementById('tblCihazlarGovde');
    const bosMesaj = document.getElementById('cihazlarBos');
    const yukleniyorMesaj = document.getElementById('cihazlarYukleniyor');
    const btnYenile = document.getElementById('btnCihazlarYenile');
    const sayacEl = document.getElementById('cihazSayisi');
    const sonGuncellemeEl = document.getElementById('cihazlarSonGuncelleme');

    let autoRefreshHandle = null;
    const AUTO_REFRESH_MS = 30000;

    function yazabilir() {
        const bilgi = (window._oturumBilgisi) || Oturum.oturumKontrol();
        return bilgi && (bilgi.rol === 'admin' || bilgi.rol === 'yonetici');
    }

    const KAYNAK_BADGE = {
        'dhcp':     { metin: 'DHCP', cls: 'bg-blue-50 text-birincil' },
        'arp':      { metin: 'ARP', cls: 'bg-slate-100 text-metin-ikincil' },
        'dhcp+arp': { metin: 'DHCP + ARP', cls: 'bg-green-50 text-durum-basarili' },
    };

    function macKisalt(mac) {
        if (!mac) return '—';
        // Basit görsel: AA:BB:CC:**:**:FF gibi orta kısmı maskele? hayır, full göster
        return mac.toUpperCase();
    }

    function tarihKisalt(iso) {
        if (!iso) return '—';
        try {
            const t = new Date(iso);
            return t.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch { return '—'; }
    }

    async function cihazlariYukle() {
        if (!tblGovde) return;
        try {
            const yanit = await Oturum.apiIstegi('/api/baglantili-cihazlar');
            if (!yanit || !yanit.ok) return;
            const cihazlar = await yanit.json();

            if (yukleniyorMesaj) yukleniyorMesaj.classList.add('hidden');
            if (sayacEl) sayacEl.textContent = cihazlar.length.toString();
            if (sonGuncellemeEl) {
                const simdi = new Date().toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                sonGuncellemeEl.textContent = `Son güncelleme: ${simdi}`;
            }

            tblGovde.innerHTML = '';
            if (bosMesaj) bosMesaj.classList.toggle('hidden', cihazlar.length > 0);
            if (cihazlar.length === 0) return;

            const yazma = yazabilir();

            cihazlar.forEach(c => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-slate-50 transition-colors';

                const kaynak = KAYNAK_BADGE[c.kaynak] || { metin: c.kaynak, cls: 'bg-slate-100 text-metin-ikincil' };
                const kaynakBadge = `<span class="px-2 py-0.5 ${kaynak.cls} text-2xs font-medium rounded-full">${kaynak.metin}</span>`;
                const hostMetin = c.host_adi ? `<span class="text-metin-birincil">${c.host_adi}</span>` : '<span class="text-metin-ucuncul italic">bilinmiyor</span>';

                const islemHucresi = yazma ? `
                    <button class="btn-cihaz-engelle px-2.5 py-1 bg-red-50 hover:bg-durum-kritik hover:text-white text-durum-kritik text-2xs font-semibold rounded-md transition-colors flex items-center gap-1"
                            data-ip="${c.ip_adresi}" data-mac="${c.mac_adresi}" title="Bu IP için engelleme kuralı oluştur">
                        <span class="material-symbols-outlined text-sm">block</span> Engelle
                    </button>` : '<span class="text-metin-ucuncul text-xs">—</span>';

                row.innerHTML = `
                    <td class="px-4 py-3 font-kod text-metin-birincil font-semibold">${c.ip_adresi || '—'}</td>
                    <td class="px-4 py-3 font-kod text-xs text-metin-ikincil">${macKisalt(c.mac_adresi)}</td>
                    <td class="px-4 py-3 text-sm">${hostMetin}</td>
                    <td class="px-4 py-3">${kaynakBadge}</td>
                    <td class="px-4 py-3 hidden md:table-cell text-xs font-kod text-metin-ucuncul">${c.arayuz || '—'}</td>
                    <td class="px-4 py-3 hidden lg:table-cell text-xs font-kod text-metin-ucuncul">${tarihKisalt(c.son_gorulme)}</td>
                    <td class="px-4 py-3 text-right">
                        <div class="flex justify-end">${islemHucresi}</div>
                    </td>
                `;
                tblGovde.appendChild(row);
            });

            if (yazma) {
                tblGovde.querySelectorAll('.btn-cihaz-engelle').forEach(btn => {
                    btn.addEventListener('click', cihazEngelle);
                });
            }
        } catch (hata) {
            console.error("Cihazlar yüklenemedi:", hata);
            if (yukleniyorMesaj) {
                yukleniyorMesaj.innerHTML = '<span class="material-symbols-outlined text-durum-kritik">error</span><p class="mt-2 text-durum-kritik">Bağlantı hatası</p>';
            }
        }
    }

    async function cihazEngelle(e) {
        const btn = e.currentTarget;
        const ip = btn.getAttribute('data-ip');
        const mac = btn.getAttribute('data-mac');
        if (!ip) return;

        if (!confirm(`${ip} (${mac}) cihazını engellemek için bir güvenlik kuralı oluşturulacak.\n\nDevam edilsin mi?`)) {
            return;
        }

        const eskiHtml = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">progress_activity</span> Engelleniyor...';

        const kural = {
            kural_adi: `Hızlı Engelle — ${ip}`,
            yon: 'giris',
            protokol: 'herhangi',
            eylem: 'engelle',
            kaynak_ip: ip,
            hedef_tip: 'ip',
            hedef_adres: null,
            hedef_port: null,
            kaynak_port: null,
            oncelik: 30,
            aktif: true,
            zaman_baslangic: null,
            zaman_bitis: null,
            aciklama: `Bağlı Cihazlar sekmesinden hızlı engelleme. MAC: ${mac || 'bilinmiyor'}`,
        };

        try {
            const yanit = await Oturum.apiIstegi('/api/kurallar', {
                method: 'POST',
                body: JSON.stringify(kural)
            });
            if (yanit && yanit.ok) {
                btn.innerHTML = '<span class="material-symbols-outlined text-sm">check</span> Engellendi';
                btn.classList.remove('bg-red-50', 'text-durum-kritik');
                btn.classList.add('bg-green-50', 'text-durum-basarili');
                setTimeout(() => {
                    btn.disabled = false;
                    btn.innerHTML = eskiHtml;
                    btn.classList.remove('bg-green-50', 'text-durum-basarili');
                    btn.classList.add('bg-red-50', 'text-durum-kritik');
                }, 2500);
            } else {
                const err = yanit ? await yanit.json() : null;
                alert(`Engelleme başarısız: ${(err && err.detail) || 'Bilinmeyen hata'}`);
                btn.disabled = false;
                btn.innerHTML = eskiHtml;
            }
        } catch (hata) {
            console.error("Engelleme hatası:", hata);
            alert('Bağlantı hatası');
            btn.disabled = false;
            btn.innerHTML = eskiHtml;
        }
    }

    function autoRefreshBaslat() {
        autoRefreshDurdur();
        autoRefreshHandle = setInterval(cihazlariYukle, AUTO_REFRESH_MS);
    }

    function autoRefreshDurdur() {
        if (autoRefreshHandle) {
            clearInterval(autoRefreshHandle);
            autoRefreshHandle = null;
        }
    }

    if (btnYenile) {
        btnYenile.addEventListener('click', cihazlariYukle);
    }

    // Sekmeye girilince yükle + auto-refresh başlat
    document.addEventListener('sekmeYuklendi:cihazlar', () => {
        cihazlariYukle();
        autoRefreshBaslat();
    });

    // Diğer sekmeye geçince auto-refresh'i durdur (gereksiz API yükü olmasın)
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#', '');
        if (hash !== 'cihazlar') autoRefreshDurdur();
    });
});
