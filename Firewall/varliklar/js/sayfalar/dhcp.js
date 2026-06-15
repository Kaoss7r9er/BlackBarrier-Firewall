/**
 * Black Barrier — DHCP Sekmesi
 * Backend endpoint'leri:
 *   GET  /api/dhcp/{arayuz}              → ayarları yükle
 *   PUT  /api/dhcp/{arayuz}              → ayarları kaydet
 *   GET  /api/dhcp/{arayuz}/kiralamalar  → aktif kiralamalar
 *
 * Şema: sema.sql 'dhcp_ayarlari' tablosu — LAN ve OPT_VLAN_1 varsayılan satırlar.
 */

document.addEventListener('DOMContentLoaded', () => {

    const FORM_ID_HARITASI = {
        aktif: 'dhcpAktif',
        interface_adi: 'dhcpInterfaceAdi',
        alt_ag: 'dhcpAltAg',
        alt_ag_maskesi: 'dhcpAltAgMaskesi',
        ag_gecidi: 'dhcpAgGecidi',
        dns_sunuculari: 'dhcpDns',
        havuz_baslangic: 'dhcpHavuzBaslangic',
        havuz_bitis: 'dhcpHavuzBitis',
        kira_suresi: 'dhcpKiraSuresi',
    };

    const arayuzSekmeleri = document.getElementById('dhcpArayuzSekmeleri');
    const arayuzEtiket = document.getElementById('dhcpArayuzEtiket');
    const btnKaydet = document.getElementById('btnDhcpKaydet');
    const btnYenile = document.getElementById('btnDhcpKiralamalariYenile');
    const btnOtomatik = document.getElementById('btnDhcpOtomatik');
    const tblGovde = document.getElementById('tblDhcpKiralamalariGovde');
    const bosMesaj = document.getElementById('dhcpKiralamalariBos');
    const durumKutusu = document.getElementById('dhcpDurum');

    let aktifArayuz = 'LAN';

    // ═══════════════════════════════════════
    //  RBAC — İzleyici salt-okunur
    // ═══════════════════════════════════════
    function yetkiUygula() {
        const yazabilir = !window.Oturum || Oturum.yazabilir();
        // Yazma butonlarını gizle
        [btnKaydet, btnOtomatik].forEach(b => { if (b) b.style.display = yazabilir ? '' : 'none'; });
        // Form alanlarını salt-okunur yap
        Object.values(FORM_ID_HARITASI).forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = !yazabilir;
        });
    }

    // ═══════════════════════════════════════
    //  ARAYÜZ SEKMESİ
    // ═══════════════════════════════════════
    function arayuzSekmesiniGuncelle() {
        if (!arayuzSekmeleri) return;
        arayuzSekmeleri.querySelectorAll('.dhcp-arayuz-btn').forEach(btn => {
            const seciliMi = btn.getAttribute('data-arayuz') === aktifArayuz;
            if (seciliMi) {
                btn.className = 'dhcp-arayuz-btn px-4 py-1.5 bg-birincil text-white text-xs font-semibold rounded-md shadow-yumusak';
            } else {
                btn.className = 'dhcp-arayuz-btn px-4 py-1.5 text-metin-ikincil text-xs font-medium hover:bg-white rounded-md transition-colors';
            }
        });
        if (arayuzEtiket) arayuzEtiket.textContent = aktifArayuz;
    }

    if (arayuzSekmeleri) {
        arayuzSekmeleri.addEventListener('click', (e) => {
            const btn = e.target.closest('.dhcp-arayuz-btn');
            if (!btn) return;
            const yeni = btn.getAttribute('data-arayuz');
            if (yeni && yeni !== aktifArayuz) {
                aktifArayuz = yeni;
                arayuzSekmesiniGuncelle();
                ayarlariYukle();
                kiralamalariYukle();
            }
        });
    }

    // ═══════════════════════════════════════
    //  DURUM MESAJI
    // ═══════════════════════════════════════
    function durumGoster(metin, tip = 'basari') {
        if (!durumKutusu) return;
        durumKutusu.textContent = metin;
        durumKutusu.classList.remove('hidden', 'bg-green-50', 'text-durum-basarili',
                                      'bg-red-50', 'text-durum-kritik');
        if (tip === 'basari') {
            durumKutusu.classList.add('bg-green-50', 'text-durum-basarili');
        } else {
            durumKutusu.classList.add('bg-red-50', 'text-durum-kritik');
        }
        setTimeout(() => durumKutusu.classList.add('hidden'), 3000);
    }

    // ═══════════════════════════════════════
    //  AYARLARI YÜKLE
    // ═══════════════════════════════════════
    async function ayarlariYukle() {
        try {
            const yanit = await Oturum.apiIstegi(`/api/dhcp/${encodeURIComponent(aktifArayuz)}`);
            if (!yanit) return;
            if (yanit.status === 404) {
                // Arayüz DB'de tanımlı değil — formu varsayılanlarla bırak
                _formuTemizle();
                return;
            }
            if (!yanit.ok) return;

            const ayarlar = await yanit.json();
            Object.entries(FORM_ID_HARITASI).forEach(([anahtar, id]) => {
                const el = document.getElementById(id);
                if (!el) return;
                const deger = ayarlar[anahtar];
                if (anahtar === 'aktif') {
                    el.checked = !!deger;
                } else if (deger !== null && deger !== undefined) {
                    el.value = deger;
                } else {
                    el.value = '';
                }
            });
        } catch (hata) {
            console.error("DHCP ayarları yüklenemedi:", hata);
        }
    }

    function _formuTemizle() {
        Object.entries(FORM_ID_HARITASI).forEach(([anahtar, id]) => {
            const el = document.getElementById(id);
            if (!el) return;
            if (anahtar === 'aktif') el.checked = false;
            else el.value = '';
        });
    }

    // ═══════════════════════════════════════
    //  OTOMATİK DOLDUR (ağ geçidinden türet)
    // ═══════════════════════════════════════
    function otomatikDoldur() {
        const gw = (document.getElementById('dhcpAgGecidi')?.value || '').trim();
        const m = gw.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (!m) {
            durumGoster('Önce "Ağ Geçidi" alanına firewall\'ın LAN IP\'sini yaz (örn. 192.168.1.1).', 'hata');
            return;
        }
        const taban = `${m[1]}.${m[2]}.${m[3]}`;
        const setDeger = (id, deger) => { const el = document.getElementById(id); if (el) el.value = deger; };
        setDeger('dhcpAltAg', `${taban}.0`);
        setDeger('dhcpAltAgMaskesi', '255.255.255.0');
        setDeger('dhcpHavuzBaslangic', `${taban}.50`);
        setDeger('dhcpHavuzBitis', `${taban}.200`);
        const dnsEl = document.getElementById('dhcpDns');
        if (dnsEl && !dnsEl.value.trim()) dnsEl.value = gw;   // DNS=firewall → domain engelleme istemcide de çalışır
        durumGoster('Yaygın değerlerle dolduruldu — kontrol edip Kaydet\'e bas.', 'basari');
    }

    // ═══════════════════════════════════════
    //  AYARLARI KAYDET
    // ═══════════════════════════════════════
    async function ayarlariKaydet() {
        const govde = {};
        Object.entries(FORM_ID_HARITASI).forEach(([anahtar, id]) => {
            const el = document.getElementById(id);
            if (!el) return;
            if (anahtar === 'aktif') {
                govde[anahtar] = el.checked;
            } else if (anahtar === 'kira_suresi') {
                const sayi = parseInt(el.value, 10);
                govde[anahtar] = Number.isFinite(sayi) && sayi >= 300 ? sayi : 86400;
            } else {
                govde[anahtar] = el.value.trim() || null;
            }
        });

        // DHCP aktif edilecekse interface_adi zorunlu (dnsmasq config üretimi için)
        if (govde.aktif && !govde.interface_adi) {
            durumGoster('DHCP aktifleştirmek için Sistem Arayüzü alanı zorunlu', 'hata');
            return;
        }

        if (btnKaydet) {
            btnKaydet.disabled = true;
            btnKaydet.innerHTML = '<span class="material-symbols-outlined text-base animate-spin">progress_activity</span> Kaydediliyor...';
        }

        try {
            const yanit = await Oturum.apiIstegi(`/api/dhcp/${encodeURIComponent(aktifArayuz)}`, {
                method: 'PUT',
                body: JSON.stringify(govde),
            });
            if (yanit && yanit.ok) {
                durumGoster('DHCP ayarları kaydedildi', 'basari');
                kiralamalariYukle();
            } else {
                const err = yanit ? await yanit.json() : null;
                durumGoster((err && err.detail) || 'Kayıt başarısız', 'hata');
            }
        } catch (hata) {
            console.error("DHCP kaydetme hatası:", hata);
            durumGoster('Bağlantı hatası', 'hata');
        } finally {
            if (btnKaydet) {
                btnKaydet.disabled = false;
                btnKaydet.innerHTML = '<span class="material-symbols-outlined text-base">save</span> Kaydet';
            }
        }
    }

    // ═══════════════════════════════════════
    //  KİRALAMALAR
    // ═══════════════════════════════════════
    async function kiralamalariYukle() {
        if (!tblGovde) return;
        try {
            const yanit = await Oturum.apiIstegi(`/api/dhcp/${encodeURIComponent(aktifArayuz)}/kiralamalar`);
            if (!yanit || !yanit.ok) return;
            const kiralamalar = await yanit.json();
            tblGovde.innerHTML = '';

            if (bosMesaj) bosMesaj.style.display = kiralamalar.length === 0 ? '' : 'none';

            kiralamalar.forEach(k => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-slate-50';

                const bitis = k.kira_bitis ? new Date(k.kira_bitis) : null;
                const sureMetni = bitis
                    ? bitis.toLocaleString('tr-TR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
                    : '—';

                const durum = (k.durum || 'aktif').toLowerCase();
                let durumBadge;
                if (durum === 'aktif') {
                    durumBadge = '<span class="px-2 py-0.5 bg-green-50 text-durum-basarili text-2xs font-medium rounded-full">Aktif</span>';
                } else if (durum === 'suresi_dolmus') {
                    durumBadge = '<span class="px-2 py-0.5 bg-red-50 text-durum-kritik text-2xs font-medium rounded-full">Süresi dolmuş</span>';
                } else {
                    durumBadge = `<span class="px-2 py-0.5 bg-slate-100 text-metin-ikincil text-2xs font-medium rounded-full">${k.durum}</span>`;
                }

                row.innerHTML = `
                    <td class="px-4 py-3 font-kod text-metin-birincil">${k.ip_adresi || '—'}</td>
                    <td class="px-4 py-3 font-kod text-metin-ikincil">${k.mac_adresi || '—'}</td>
                    <td class="px-4 py-3 text-metin-ikincil">${k.host_adi || '—'}</td>
                    <td class="px-4 py-3 text-metin-ucuncul text-xs font-kod">${sureMetni}</td>
                    <td class="px-4 py-3">${durumBadge}</td>
                `;
                tblGovde.appendChild(row);
            });
        } catch (hata) {
            console.error("DHCP kiralamaları yüklenemedi:", hata);
        }
    }

    // ═══════════════════════════════════════
    //  EVENT BAĞLAMA
    // ═══════════════════════════════════════
    if (btnKaydet) {
        btnKaydet.addEventListener('click', (e) => {
            e.preventDefault();
            ayarlariKaydet();
        });
    }
    if (btnYenile) {
        btnYenile.addEventListener('click', (e) => {
            e.preventDefault();
            kiralamalariYukle();
        });
    }
    if (btnOtomatik) {
        btnOtomatik.addEventListener('click', (e) => {
            e.preventDefault();
            otomatikDoldur();
        });
    }

    document.addEventListener('sekmeYuklendi:dhcp', () => {
        arayuzSekmesiniGuncelle();
        ayarlariYukle();
        kiralamalariYukle();
        yetkiUygula();
    });
});
