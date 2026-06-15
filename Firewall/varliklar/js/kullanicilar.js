/**
 * Black Barrier — Kullanıcı Yönetimi
 * Roller: admin (tam yetki), yonetici (kullanıcı yönetimi hariç), izleyici (salt okunur)
 */

document.addEventListener('DOMContentLoaded', () => {

    const kullaniciTabloGovdesi = document.getElementById('tblKullanicilarGovde');
    const modalKullaniciEkle = document.getElementById('modalKullaniciEkle');
    const formKullaniciEkle = document.getElementById('formKullaniciEkle');
    const modalKullaniciHata = document.getElementById('modalKullaniciHata');
    const btnKullaniciKaydet = document.getElementById('btnKullaniciKaydet');
    const modalKullaniciBaslik = document.getElementById('modalKullaniciBaslik');
    const modalSifre = document.getElementById('modalSifre');
    const modalSifreNot = document.getElementById('modalSifreNot');
    const btnSifreGoster = document.getElementById('btnSifreGoster');

    let guncellenecekKullaniciId = null;

    // ── Rol kartları (radio) yardımcıları ──
    function seciliRol() {
        const r = document.querySelector('input[name="modalKullaniciRol"]:checked');
        return r ? r.value : 'yonetici';
    }
    function rolSec(rol) {
        const hedef = document.querySelector(`input[name="modalKullaniciRol"][value="${rol || 'yonetici'}"]`)
            || document.querySelector('input[name="modalKullaniciRol"][value="yonetici"]');
        if (hedef) hedef.checked = true;
    }

    // ── Şifre göster/gizle ──
    if (btnSifreGoster && modalSifre) {
        btnSifreGoster.addEventListener('click', () => {
            const gizli = modalSifre.type === 'password';
            modalSifre.type = gizli ? 'text' : 'password';
            const ikon = btnSifreGoster.querySelector('.material-symbols-outlined');
            if (ikon) ikon.textContent = gizli ? 'visibility_off' : 'visibility';
        });
    }

    // Sadece admin kullanıcı yönetimi yapabilir (backend de zorlar)
    function adminMi() {
        const bilgi = (window._oturumBilgisi) || Oturum.oturumKontrol();
        return bilgi && bilgi.rol === 'admin';
    }

    // ═══════════════════════════════════════
    //  MODAL SEKME YÖNETİMİ
    // ═══════════════════════════════════════
    document.querySelectorAll('.modal-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const modal = tab.closest('.modal-giris') || tab.closest('[id^="modal"]')?.closest('.flex.flex-col');
            if (!modal) return;

            modal.querySelectorAll('.modal-tab').forEach(t => {
                t.classList.remove('aktif');
                t.classList.add('text-metin-ucuncul', 'border-transparent');
            });
            tab.classList.add('aktif');
            tab.classList.remove('text-metin-ucuncul', 'border-transparent');

            const tabName = tab.getAttribute('data-tab');
            modal.querySelectorAll('.modal-tab-content').forEach(content => {
                if (content.getAttribute('data-tab') === tabName) {
                    content.classList.remove('hidden');
                } else {
                    content.classList.add('hidden');
                }
            });
        });
    });

    // ═══════════════════════════════════════
    //  KULLANICI LİSTESİ
    // ═══════════════════════════════════════
    async function kullanicilariYukle() {
        if (!kullaniciTabloGovdesi) return;

        try {
            const yanit = await Oturum.apiIstegi('/api/kullanicilar');
            if (yanit && yanit.ok) {
                const kullanicilar = await yanit.json();
                kullaniciTabloGovdesi.innerHTML = '';
                const yukleniyorDiv = document.getElementById('kullaniciYukleniyor');
                if (yukleniyorDiv) yukleniyorDiv.classList.add('hidden');

                if (kullanicilar.length === 0) {
                    kullaniciTabloGovdesi.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-metin-ucuncul text-sm">Kullanıcı bulunamadı.</td></tr>`;
                    return;
                }

                const yonetebilir = adminMi();
                // Admin değilse "Yeni Kullanıcı" butonunu da gizle
                const btnEkle = document.getElementById('btnKullaniciEkleGorunum');
                if (btnEkle) btnEkle.style.display = yonetebilir ? '' : 'none';

                kullanicilar.forEach(k => {
                    const etiket = Oturum.rolEtiketiAl(k.rol || 'yonetici');
                    const row = document.createElement('tr');
                    row.className = 'hover:bg-slate-50 transition-colors';

                    // Son giriş (backend alanı: son_giris_t)
                    const sonGiris = k.son_giris_t
                        ? new Date(k.son_giris_t).toLocaleString('tr-TR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
                        : '—';

                    const islemHucresi = yonetebilir ? `
                        <div class="relative inline-block">
                            <button class="hamburger-btn-tablo p-1 rounded hover:bg-slate-100 text-metin-ucuncul transition-colors" data-id="${k.id}">
                                <span class="material-symbols-outlined text-lg">more_vert</span>
                            </button>
                            <div class="dropdown-menu" data-dropdown="${k.id}">
                                <button class="btn-kullanici-duzenle" data-id="${k.id}" data-kadi="${k.kullanici_adi}" data-ad="${k.ad_soyad || ''}" data-rol="${k.rol || 'yonetici'}">
                                    <span class="material-symbols-outlined text-sm">edit</span> Düzenle
                                </button>
                                <button class="btn-kullanici-sil tehlikeli" data-id="${k.id}">
                                    <span class="material-symbols-outlined text-sm">delete</span> Sil
                                </button>
                            </div>
                        </div>` : '<span class="text-metin-ucuncul text-xs">—</span>';

                    row.innerHTML = `
                        <td class="px-4 py-3">
                            <div class="flex items-center gap-2.5">
                                <div class="w-7 h-7 bg-birincil/10 text-birincil rounded-full flex items-center justify-center text-xs font-bold shrink-0">${(k.ad_soyad || k.kullanici_adi || '?').charAt(0).toUpperCase()}</div>
                                <span class="font-semibold text-metin-birincil">${k.kullanici_adi}</span>
                            </div>
                        </td>
                        <td class="px-4 py-3 text-metin-ikincil">${k.ad_soyad || '—'}</td>
                        <td class="px-4 py-3"><span class="${etiket.renk} px-2 py-0.5 text-2xs font-semibold rounded-full">${etiket.metin}</span></td>
                        <td class="px-4 py-3 hidden lg:table-cell text-xs text-metin-ucuncul font-kod">${sonGiris}</td>
                        <td class="px-4 py-3 text-right">${islemHucresi}</td>
                    `;
                    kullaniciTabloGovdesi.appendChild(row);
                });

                if (yonetebilir) baglantilariKur();
            }
        } catch (hata) {
            console.error("API hatası:", hata);
            const yukleniyorDiv = document.getElementById('kullaniciYukleniyor');
            if (yukleniyorDiv) {
                yukleniyorDiv.innerHTML = '<span class="material-symbols-outlined text-durum-kritik">error</span><p class="mt-1 text-durum-kritik">Bağlantı hatası</p>';
            }
        }
    }

    // ═══════════════════════════════════════
    //  HAMBURGER MENÜ
    // ═══════════════════════════════════════
    function baglantilariKur() {
        document.querySelectorAll('.hamburger-btn-tablo').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = btn.getAttribute('data-id');
                const dropdown = document.querySelector(`[data-dropdown="${id}"]`);
                document.querySelectorAll('.dropdown-menu.aktif').forEach(d => {
                    if (d !== dropdown) d.classList.remove('aktif');
                });
                dropdown.classList.toggle('aktif');
            });
        });

        document.querySelectorAll('.btn-kullanici-duzenle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const id = e.currentTarget.getAttribute('data-id');
                const kadi = e.currentTarget.getAttribute('data-kadi');
                const adSoyad = e.currentTarget.getAttribute('data-ad');
                const rol = e.currentTarget.getAttribute('data-rol');
                dropdownKapat();
                kullaniciDuzenleModaliniAc(id, kadi, adSoyad, rol);
            });
        });

        document.querySelectorAll('.btn-kullanici-sil').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const id = e.currentTarget.getAttribute('data-id');
                dropdownKapat();
                if (confirm("Bu kullanıcıyı silmek istediğinize emin misiniz?")) {
                    await kullaniciSil(id);
                }
            });
        });
    }

    function dropdownKapat() {
        document.querySelectorAll('.dropdown-menu.aktif').forEach(d => d.classList.remove('aktif'));
    }
    document.addEventListener('click', () => dropdownKapat());

    // ═══════════════════════════════════════
    //  MODAL YÖNETİMİ
    // ═══════════════════════════════════════
    function modaliAc() {
        if (!modalKullaniciEkle) return;
        guncellenecekKullaniciId = null;
        if (formKullaniciEkle) formKullaniciEkle.reset();
        rolSec('yonetici');
        const kAdi = document.getElementById('modalKullaniciAdi');
        if (kAdi) { kAdi.value = ''; kAdi.disabled = false; }
        if (modalSifre) { modalSifre.required = true; modalSifre.type = 'password'; }
        if (modalSifreNot) modalSifreNot.textContent = 'En az 4 karakter.';
        if (modalKullaniciBaslik) modalKullaniciBaslik.textContent = 'Yeni Kullanıcı';
        if (btnKullaniciKaydet) btnKullaniciKaydet.innerHTML = '<span class="material-symbols-outlined text-lg">save</span> Oluştur';
        if (modalKullaniciHata) modalKullaniciHata.classList.add('hidden');
        modalKullaniciEkle.classList.remove('hidden');
    }

    function kullaniciDuzenleModaliniAc(id, kadi, adSoyad, rol) {
        if (!modalKullaniciEkle) return;
        guncellenecekKullaniciId = id;
        if (formKullaniciEkle) formKullaniciEkle.reset();
        if (modalKullaniciHata) modalKullaniciHata.classList.add('hidden');

        const kAdi = document.getElementById('modalKullaniciAdi');
        if (kAdi) {
            kAdi.value = kadi || '';
            kAdi.disabled = true;   // kullanıcı adı değiştirilemez
        }
        const adEl = document.getElementById('modalAdSoyad');
        if (adEl) adEl.value = adSoyad || '';
        rolSec(rol);
        if (modalSifre) { modalSifre.required = false; modalSifre.type = 'password'; }
        if (modalSifreNot) modalSifreNot.textContent = 'Şifreyi değiştirmek istemiyorsan boş bırak.';
        if (modalKullaniciBaslik) modalKullaniciBaslik.textContent = 'Kullanıcıyı Düzenle';
        if (btnKullaniciKaydet) btnKullaniciKaydet.innerHTML = '<span class="material-symbols-outlined text-lg">save</span> Kaydet';

        modalKullaniciEkle.classList.remove('hidden');
    }

    async function kullaniciSil(id) {
        try {
            const yanit = await Oturum.apiIstegi(`/api/kullanicilar/${id}`, { method: 'DELETE' });
            if (yanit && yanit.ok) {
                kullanicilariYukle();
            } else {
                const err = yanit ? await yanit.json() : null;
                alert((err && err.detail) || "Kullanıcı silinemedi.");
            }
        } catch (err) {
            console.error("Silme hatası:", err);
        }
    }

    function modaliKapat() {
        if (!modalKullaniciEkle) return;
        modalKullaniciEkle.classList.add('hidden');
        if (formKullaniciEkle) formKullaniciEkle.reset();
    }

    // Event Delegation
    document.addEventListener('click', (e) => {
        if (e.target.closest('#btnKullaniciEkleGorunum')) modaliAc();
        if (e.target.closest('#btnKullaniciModalKapat')) modaliKapat();
        if (e.target.closest('#btnKullaniciModalIptal')) modaliKapat();
        if (e.target === modalKullaniciEkle) modaliKapat();
    });

    // Form Gönderimi
    if (formKullaniciEkle) {
        formKullaniciEkle.addEventListener('submit', async (e) => {
            e.preventDefault();

            const kullaniciAdi = document.getElementById('modalKullaniciAdi')?.value.trim();
            const adSoyad = document.getElementById('modalAdSoyad')?.value.trim() || '';
            const sifre = document.getElementById('modalSifre')?.value || '';
            const rol = seciliRol();

            // Yeni kullanıcı oluştururken ad ve şifre zorunlu, düzenlemede şifre opsiyonel
            if (!guncellenecekKullaniciId && (!kullaniciAdi || !sifre)) {
                if (modalKullaniciHata) {
                    modalKullaniciHata.textContent = "Kullanıcı adı ve şifre zorunludur.";
                    modalKullaniciHata.classList.remove('hidden');
                }
                return;
            }
            if (!guncellenecekKullaniciId && sifre.length < 4) {
                if (modalKullaniciHata) {
                    modalKullaniciHata.textContent = "Şifre en az 4 karakter olmalı.";
                    modalKullaniciHata.classList.remove('hidden');
                }
                return;
            }

            if (btnKullaniciKaydet) {
                btnKullaniciKaydet.disabled = true;
                btnKullaniciKaydet.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">progress_activity</span> Kaydediliyor...';
            }
            if (modalKullaniciHata) modalKullaniciHata.classList.add('hidden');

            try {
                let yanit;
                if (guncellenecekKullaniciId) {
                    const govde = { ad_soyad: adSoyad, rol };
                    if (sifre) govde.sifre = sifre;
                    yanit = await Oturum.apiIstegi(`/api/kullanicilar/${guncellenecekKullaniciId}`, {
                        method: 'PUT',
                        body: JSON.stringify(govde)
                    });
                } else {
                    yanit = await Oturum.apiIstegi('/api/kullanicilar', {
                        method: 'POST',
                        body: JSON.stringify({ kullanici_adi: kullaniciAdi, sifre, ad_soyad: adSoyad, rol })
                    });
                }

                if (yanit && yanit.ok) {
                    modaliKapat();
                    kullanicilariYukle();
                } else {
                    const hataVeri = yanit ? await yanit.json() : null;
                    if (modalKullaniciHata) {
                        modalKullaniciHata.textContent = (hataVeri && hataVeri.detail) ? hataVeri.detail : "İşlem sırasında hata oluştu.";
                        modalKullaniciHata.classList.remove('hidden');
                    }
                }
            } catch (hata) {
                if (modalKullaniciHata) {
                    modalKullaniciHata.textContent = "Bağlantı hatası!";
                    modalKullaniciHata.classList.remove('hidden');
                }
            } finally {
                if (btnKullaniciKaydet) {
                    btnKullaniciKaydet.disabled = false;
                    btnKullaniciKaydet.innerHTML = '<span class="material-symbols-outlined text-sm">save</span> Kaydet';
                }
            }
        });
    }

    // Arama filtresi
    const araKullanici = document.getElementById('araKullanici');
    if (araKullanici) {
        araKullanici.addEventListener('input', (e) => {
            const aramaMetni = e.target.value.toLowerCase();
            if (!kullaniciTabloGovdesi) return;
            kullaniciTabloGovdesi.querySelectorAll('tr').forEach(row => {
                const metin = row.textContent.toLowerCase();
                row.style.display = metin.includes(aramaMetni) ? '' : 'none';
            });
        });
    }

    document.addEventListener('sekmeYuklendi:kullanici_yonetimi', () => {
        kullanicilariYukle();
    });
});
