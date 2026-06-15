/**
 * Black Barrier — Ana Uygulama Scripti (app.js)
 * Panel üzerindeki ortak bileşenlerin (sağ panel vb.) yönetimini sağlar.
 */

document.addEventListener('DOMContentLoaded', () => {

    // Sağ paneldeki son sistem loglarını API'den çek ve göster
    async function sistemLoglariniGetir() {
        const logKutusu = document.getElementById('sagPanelSistemLoglari');
        if (!logKutusu) return;

        try {
            // Sadece son 5 olayı alalım ki UI taşmasın
            const yanit = await Oturum.apiIstegi('/api/sistem-loglari?limit=5');
            if (yanit && yanit.ok) {
                const loglar = await yanit.json();

                if (loglar.length === 0) {
                    logKutusu.innerHTML = '<span class="text-slate-400 font-kod text-xs uppercase">Kayıt Bulunamadı</span>';
                    logKutusu.classList.add('text-center');
                    return;
                }

                logKutusu.classList.remove('text-center');
                logKutusu.innerHTML = ''; // Temizle

                loglar.forEach(log => {
                    // Olay türüne göre ikon ve renk belirle
                    let ikon = 'info';
                    let renkCls = 'text-birincil';
                    let bgCls = 'bg-blue-50';
                    let borderCls = 'border-birincil';

                    if (log.olay_turu === 'yeniden_baslatma') {
                        ikon = 'restart_alt';
                        renkCls = 'text-durum-uyari';
                        bgCls = 'bg-orange-50';
                        borderCls = 'border-durum-uyari';
                    } else if (log.olay_turu === 'hata') {
                        ikon = 'error';
                        renkCls = 'text-durum-kritik';
                        bgCls = 'bg-red-50';
                        borderCls = 'border-durum-kritik';
                    } else if (log.olay_turu === 'durma') {
                        ikon = 'stop_circle';
                        renkCls = 'text-slate-600';
                        bgCls = 'bg-slate-100';
                        borderCls = 'border-slate-400';
                    } else if (log.olay_turu === 'baslangic') {
                        ikon = 'play_circle';
                        renkCls = 'text-durum-basarili';
                        bgCls = 'bg-green-50';
                        borderCls = 'border-durum-basarili';
                    }

                    // Tarih formatlama
                    const tarih = new Date(log.zaman);
                    const saatFormati = tarih.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
                    const tarihFormati = tarih.toLocaleDateString('tr-TR', { day: '2-digit', month: '2-digit' });

                    const div = document.createElement('div');
                    div.className = `flex flex-col text-left border-l-2 ${borderCls} ${bgCls} p-2.5 rounded-r-lg relative group cursor-default mb-2`;
                    
                    div.innerHTML = `
                        <div class="flex items-center justify-between mb-1">
                            <div class="flex items-center gap-1 ${renkCls}">
                                <span class="material-symbols-outlined text-[14px]">${ikon}</span>
                                <span class="text-[10px] font-bold uppercase">${log.olay_turu.replace('_', ' ')}</span>
                            </div>
                            <span class="text-[9px] font-kod text-slate-500">${tarihFormati} ${saatFormati}</span>
                        </div>
                        <p class="text-[11px] font-kod text-slate-700 leading-tight">${log.aciklama}</p>
                    `;

                    logKutusu.appendChild(div);
                });
            }
        } catch (hata) {
            console.error("Sistem logları çekilemedi:", hata);
        }
    }

    // İlk yüklemede çalıştır
    sistemLoglariniGetir();

    // ── Güvenlik Duvarı Durum Göstergesi (yalnızca bilgi) ──────
    // Kapatma butonu kaldırıldı; burada sadece sidebar'daki durum noktası/metni
    // backend'den senkronlanır (güvenlik duvarı UI'dan kapatılamaz).
    const firewallDurumIkon = document.getElementById('firewallDurumIkon');
    const firewallDurumMetin = document.getElementById('firewallDurumMetin');

    function fwUiGuncelle(aktifMi) {
        if (aktifMi) {
            if (firewallDurumIkon) firewallDurumIkon.className = "size-2.5 bg-durum-basarili rounded-full animasyon-nabiz-yavas shadow-parlama-basarili";
            if (firewallDurumMetin) {
                firewallDurumMetin.textContent = "Güvenlik Duvarı Çevrimiçi";
                firewallDurumMetin.className = "sidebar-metin text-xs font-semibold text-metin-birincil";
            }
        } else {
            if (firewallDurumIkon) firewallDurumIkon.className = "size-2.5 bg-durum-kritik rounded-full";
            if (firewallDurumMetin) {
                firewallDurumMetin.textContent = "Güvenlik Duvarı Devre Dışı";
                firewallDurumMetin.className = "sidebar-metin text-xs font-semibold text-durum-kritik";
            }
        }
    }

    async function firewallDurumSenkronizeEt() {
        try {
            const yanit = await Oturum.apiIstegi('/api/firewall/durum');
            if (yanit && yanit.ok) {
                const veri = await yanit.json();
                fwUiGuncelle(veri.aktif);
            }
        } catch (hata) {
            console.error("Firewall senkronizasyon hatası:", hata);
        }
    }

    setInterval(firewallDurumSenkronizeEt, 15000);
    firewallDurumSenkronizeEt();

});
