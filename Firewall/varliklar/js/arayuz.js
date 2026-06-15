/**
 * Black Barrier — Arayüz Etkileşimleri (UI Scripts)
 * Profil menüsü, SPA routing, sidebar resize/collapse/mobile
 */

document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════
    //  PROFİL MENÜSÜ
    // ═══════════════════════════════════════
    const profilButonu = document.getElementById('profilButonu');
    const profilMenusu = document.getElementById('profilMenusu');

    if (profilButonu && profilMenusu) {
        profilButonu.addEventListener('click', (e) => {
            e.stopPropagation();
            profilMenusu.classList.toggle('hidden');
        });

        document.addEventListener('click', (e) => {
            if (!profilMenusu.contains(e.target) && !profilButonu.contains(e.target)) {
                profilMenusu.classList.add('hidden');
            }
        });

        profilMenusu.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }

    // ═══════════════════════════════════════
    //  SPA YÖNLENDİRME MOTORU
    // ═══════════════════════════════════════
    function sayfayiGuncelle() {
        // Hash yoksa (ilk açılış) kullanıcının seçtiği "varsayılan açılış sayfası" kullanılır.
        const varsayilanSekme = localStorage.getItem('bb_acilis_sayfasi') || 'dashboard';
        let hash = window.location.hash.replace('#', '') || varsayilanSekme;
        
        // 1. Tüm görünümleri gizle
        const tumGorunumler = document.querySelectorAll('.gorunum-alani');
        tumGorunumler.forEach(gorunum => {
            gorunum.classList.add('hidden');
            gorunum.classList.remove('flex');
        });

        // 2. Hedef görünümü bul ve göster
        const hedefGorunum = document.getElementById('gorunum-' + hash);
        if (hedefGorunum) {
            hedefGorunum.classList.remove('hidden');
            hedefGorunum.classList.add('flex');
            
            // 3. İlgili modülleri haberdar et
            document.dispatchEvent(new CustomEvent(`sekmeYuklendi:${hash}`));
        } else {
            console.warn(`Görünüm bulunamadı: gorunum-${hash}`);
            const anaG = document.getElementById('gorunum-dashboard');
            if(anaG) {
                anaG.classList.remove('hidden');
                anaG.classList.add('flex');
                document.dispatchEvent(new CustomEvent(`sekmeYuklendi:dashboard`));
            }
        }

        // 4. Sidebar aktif durumunu güncelle
        const sidebarLinkleri = document.querySelectorAll('#sidebar nav a[href^="#"]');
        sidebarLinkleri.forEach(link => {
            const isActive = link.getAttribute('href') === `#${hash}`;
            
            if (isActive) {
                link.classList.add('bg-birincil/10', 'text-birincil', 'font-semibold', 'border-birincil');
                link.classList.remove('text-metin-ikincil', 'hover:bg-slate-100', 'border-transparent');
                const ikon = link.querySelector('span.material-symbols-outlined');
                if (ikon) ikon.classList.add('text-birincil');
            } else {
                link.classList.remove('bg-birincil/10', 'text-birincil', 'font-semibold', 'border-birincil');
                link.classList.add('text-metin-ikincil', 'hover:bg-slate-100', 'border-transparent');
                const ikon = link.querySelector('span.material-symbols-outlined');
                if (ikon) ikon.classList.remove('text-birincil');
            }
        });

        // 5. Mobilde sidebar'ı kapat
        if (window.innerWidth <= 768) {
            sidebarKapat();
        }
    }

    window.addEventListener('hashchange', sayfayiGuncelle);
    // İlk yükleme (F5): sayfayiGuncelle 'sekmeYuklendi:<sekme>' olayını gönderir.
    // Bunu setTimeout(0) ile bir sonraki tick'e ertele — böylece tüm sayfa
    // modülleri (kurallar.js, trafik.js vs.) DOMContentLoaded içinde kendi
    // 'sekmeYuklendi' dinleyicilerini KAYDETMİŞ olur. Aksi halde arayuz.js'in
    // handler'ı önce çalışıp olayı boşa gönderir ve F5'te aktif sekme (kurallar
    // dahil) verisini yüklemez — "kurallar siliniyor" gibi görünür.
    setTimeout(sayfayiGuncelle, 0);

    // ═══════════════════════════════════════
    //  SIDEBAR — SÜRÜKLENEBİLİR (RESIZE)
    // ═══════════════════════════════════════
    const sidebar = document.getElementById('sidebar');
    const resizeHandle = document.getElementById('sidebarResizeHandle');

    // Kullanıcı tercihi: kenar çubuğu başlangıçta daraltılmış açılsın
    if (sidebar && localStorage.getItem('bb_kenar_cubugu_dar') === '1') {
        sidebar.classList.add('collapsed');
        sidebar.style.width = '60px';
    }

    if (sidebar && resizeHandle) {
        let isResizing = false;
        let startX = 0;
        let startWidth = 0;

        resizeHandle.addEventListener('mousedown', (e) => {
            isResizing = true;
            startX = e.clientX;
            startWidth = sidebar.offsetWidth;
            resizeHandle.classList.add('active');
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
            e.preventDefault();
        });

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;
            const diff = e.clientX - startX;
            const newWidth = Math.max(60, Math.min(400, startWidth + diff));
            sidebar.style.setProperty('--sidebar-width', newWidth + 'px');
            sidebar.style.width = newWidth + 'px';
            
            // 80px'den küçükse otomatik daralt
            if (newWidth <= 80) {
                sidebar.classList.add('collapsed');
            } else {
                sidebar.classList.remove('collapsed');
            }
        });

        document.addEventListener('mouseup', () => {
            if (isResizing) {
                isResizing = false;
                resizeHandle.classList.remove('active');
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
            }
        });
    }

    // ═══════════════════════════════════════
    //  SIDEBAR — DARALTMA (COLLAPSE)
    // ═══════════════════════════════════════
    const btnSidebarDaralt = document.getElementById('btnSidebarDaralt');
    if (btnSidebarDaralt && sidebar) {
        btnSidebarDaralt.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            if (sidebar.classList.contains('collapsed')) {
                sidebar.style.width = '60px';
            } else {
                sidebar.style.width = '260px';
            }
        });
    }

    // ═══════════════════════════════════════
    //  SIDEBAR — MOBİL (HAMBURGER)
    // ═══════════════════════════════════════
    const btnHamburger = document.getElementById('btnHamburger');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    function sidebarAc() {
        if (!sidebar) return;
        sidebar.classList.add('mobil-acik');
        if (sidebarOverlay) sidebarOverlay.classList.add('active');
    }

    function sidebarKapat() {
        if (!sidebar) return;
        sidebar.classList.remove('mobil-acik');
        if (sidebarOverlay) sidebarOverlay.classList.remove('active');
    }

    if (btnHamburger) {
        btnHamburger.addEventListener('click', () => {
            if (sidebar.classList.contains('mobil-acik')) {
                sidebarKapat();
            } else {
                sidebarAc();
            }
        });
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', sidebarKapat);
    }

    // ═══════════════════════════════════════
    //  RBAC: İzleyici/Yönetici için sidebar gizlemeleri
    // ═══════════════════════════════════════
    //  Backend RBAC her durumda zorluyor; bu sadece UI temizliği için.
    function sidebarRolFiltresi() {
        const bilgi = window._oturumBilgisi;
        if (!bilgi) return;
        // Sadece admin "Kullanıcılar" sekmesini ve admin'e özel menü öğelerini görür
        if (bilgi.rol !== 'admin') {
            document.querySelectorAll('#sidebar nav a[href="#kullanici_yonetimi"]').forEach(a => {
                a.style.display = 'none';
            });
            document.querySelectorAll('.profil-admin-only').forEach(el => {
                el.style.display = 'none';
            });
        }
    }
    // _oturumBilgisi oturum.js içindeki DOMContentLoaded içinde set ediliyor;
    // mikrotask sonra çağırarak hazır olmasını garantile.
    queueMicrotask(sidebarRolFiltresi);

});
