"""
Black Barrier — nftables Entegrasyonu (nftables_yonetici.py)
============================================================
DB'deki güvenlik kurallarını Linux nftables komutlarına çevirir
ve subprocess ile gerçek netfilter çekirdeğine uygular.

Tasarım kararları:
- Her değişiklikte (ekle/sil/durum) 3 filter zinciri (input/forward/output)
  flush edilir, ardından DB'deki tüm aktif kurallar öncelik sırasıyla
  yeniden uygulanır. Bu yaklaşım handle takibi gerektirmez ve daima
  DB ile çekirdek senkronize kalır.
- Komutlar subprocess.run(args_list, shell=False) ile çalıştırılır.
  String birleştirme yapılmaz → komut enjeksiyon riski yok (PDF taslağı
  "tamamen ayrıştırılmış liste elemanları" gereksinimine uygun).
- BB_NFTABLES_DISABLED=1 ortam değişkeniyle çalıştırma devre dışı
  bırakılabilir (Windows/lokal dev ortamı için).

Tablo/zincir yapısı (install.sh ile uyumlu):
- Tablo:    inet blackbarrier
- Zincir:   input    (DB yon='giris')
- Zincir:   forward  (DB yon='ilet')
- Zincir:   output   (DB yon='cikis')

Servis root olarak çalıştığı için sudo gerekmez.
"""

import os
import shutil
import subprocess
import threading
from typing import Any, Iterable

# ── Yapılandırma ──────────────────────────────────────────────
NFTABLES_DEVRE_DISI = os.environ.get('BB_NFTABLES_DISABLED', '0') == '1'
TABLO_AILE = 'inet'
TABLO_ADI = 'blackbarrier'
KOMUT_TIMEOUT_SN = 5

# "Trafik İzleme" modu:
# Açıkken (BB_TRAFIK_IZLEME=1) her filter zincirinin SONUNA rate-limited
# bir "log + accept" catch-all kural eklenir. Bu, hiçbir kullanıcı kuralıyla
# eşleşmeyen paketler için de log üretir → log_toplayici → trafik_kayitlari.
# Sunum/demo için faydalı; üretimde disk I/O ve journal şişmesi yapabileceği
# için varsayılan KAPALI.
#
# Rate limit: 'limit rate 100/second' → saniyede max 100 paket loglanır,
# fazlası sessizce accept edilir. Sunumda yeterli görsel akış sağlar,
# yüksek trafikte sistemi bunaltmaz.
TRAFIK_IZLEME = os.environ.get('BB_TRAFIK_IZLEME', '0') == '1'
TRAFIK_IZLEME_RATE = os.environ.get('BB_TRAFIK_IZLEME_RATE', '100/second')

# Anti-lockout (OPNsense'deki gibi): yönetim erişimini (panel + SSH) input
# zincirinin EN ÜSTÜNDE koşulsuz kabul eder. Böylece kullanıcı bir kuralla
# (ör. 'Her yön' + geniş bir kaynağı engelle) kendini panelden/SSH'tan
# yanlışlıkla kilitleyemez. BB_ANTI_LOCKOUT=0 ile kapatılabilir.
ANTI_LOCKOUT = os.environ.get('BB_ANTI_LOCKOUT', '1') == '1'
YONETIM_PORTLARI = [
    p.strip() for p in os.environ.get('BB_YONETIM_PORTLARI', '22,8000').split(',')
    if p.strip().isdigit()
]

# NAT tablosu (install.sh ile uyumlu): install.sh 'postrouting' zincirini
# priority 100'de oluşturup default WAN masquerade ekliyor. Bizim Python
# kodumuz ayrı zincirler kullanır ki install.sh'in default kuralı yerinde
# kalsın (kullanıcı kural eklemese bile LAN→WAN NAT çalışsın).
#   bb_app_prerouting  (hook prerouting,  priority -100) → DNAT (port forward)
#   bb_app_postrouting (hook postrouting, priority  90) → SNAT / ek masquerade
# Priority 90 → install.sh'in 100'lük zincirinden ÖNCE değerlendirilir, böylece
# kullanıcı SNAT kuralı default masquerade'i override edebilir.
NAT_TABLO_ADI = 'bb_nat'
NAT_PREROUTING_CHAIN = 'bb_app_prerouting'
NAT_POSTROUTING_CHAIN = 'bb_app_postrouting'

# DB değeri → nftables zincir/eylem adı
ZINCIR_HARITASI = {
    'giris': 'input',
    'cikis': 'output',
    'ilet':  'forward',
}
EYLEM_HARITASI = {
    'izin_ver': 'accept',
    'engelle':  'drop',
    'reddet':   'reject',
}

# Yazma operasyonlarını seri hale getirmek için kilit.
# Birden fazla istek aynı anda kural değiştirirse flush+apply'ın
# araya başka bir flush+apply girmesini engeller.
_uygula_kilidi = threading.Lock()


# ══════════════════════════════════════════════════════════════
#  YARDIMCILAR
# ══════════════════════════════════════════════════════════════

def _nft_yolu() -> str | None:
    """
    nft binary'sinin tam yolunu bulur.

    KRİTİK: systemd servisinin PATH'i genelde /usr/sbin İÇERMEZ; nft ise Ubuntu'da
    /usr/sbin/nft'tedir. Bu yüzden yalnızca shutil.which('nft') (PATH) yetmez —
    bilinen konumlara da bakarız. Aksi halde servis 'nft binary bulunamadı' der
    ve hiçbir kural uygulanmaz (kabukta root PATH'inde /usr/sbin olduğu için
    çalışıyor görünür → kafa karıştırıcı).
    """
    yol = shutil.which('nft')
    if yol:
        return yol
    for aday in ('/usr/sbin/nft', '/sbin/nft', '/usr/bin/nft'):
        if os.path.exists(aday):
            return aday
    return None


# Modül yüklenince bir kez çöz (servis PATH'i eksik olsa bile çalışsın)
_NFT = _nft_yolu() or 'nft'


def nftables_kullanilabilir_mi() -> bool:
    """nft binary'si bulunabiliyor mu? (PATH + bilinen sbin konumları)"""
    return _nft_yolu() is not None


def _komut_calistir(args: list[str], sessiz: bool = False) -> tuple[int, str, str]:
    """
    subprocess.run sarmalayıcısı.
    args MUTLAKA liste olmalı; string verilirse şimşeklendirici hata fırlatır.
    sessiz=True → return code != 0 olsa da yazdırma (idempotent komutlar için).

    Döndürür: (return_code, stdout, stderr)
    """
    if not isinstance(args, list):
        raise TypeError("args bir liste olmalı — string birleştirme komut enjeksiyonu yaratır")

    # İlk eleman 'nft' ise tam yola çevir (systemd PATH'inde /usr/sbin yoksa da bulunsun)
    if args and args[0] == 'nft':
        args = [_NFT] + args[1:]

    if NFTABLES_DEVRE_DISI:
        print(f"[nft-dev] {' '.join(args)}")
        return 0, '', ''

    try:
        sonuc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=KOMUT_TIMEOUT_SN,
            check=False,
        )
        if sonuc.returncode != 0 and not sessiz:
            print(f"[nft-hata] komut={' '.join(args)} stderr={sonuc.stderr.strip()}")
        return sonuc.returncode, sonuc.stdout, sonuc.stderr
    except FileNotFoundError:
        if not sessiz:
            print("[nft-hata] 'nft' binary'si bulunamadı. nftables paketi kurulu mu?")
        return -1, '', 'nft-not-found'
    except subprocess.TimeoutExpired:
        if not sessiz:
            print(f"[nft-hata] Timeout: {' '.join(args)}")
        return -1, '', 'timeout'
    except Exception as e:
        if not sessiz:
            print(f"[nft-hata] {e}")
        return -1, '', str(e)


def _ortam_hazirla():
    """
    Tablo ve filter zincirleri yoksa oluşturur. Idempotent;
    'File exists' hataları sessizce yutulur.
    """
    _komut_calistir(
        ['nft', 'add', 'table', TABLO_AILE, TABLO_ADI],
        sessiz=True
    )
    for zincir in ZINCIR_HARITASI.values():
        # nft sözdiziminde { ... } bir tek argümandır — boşluksuz ver:
        zincir_tanim = (
            f'{{ type filter hook {zincir} priority 0 ; policy accept ; }}'
        )
        _komut_calistir(
            ['nft', 'add', 'chain', TABLO_AILE, TABLO_ADI, zincir, zincir_tanim],
            sessiz=True
        )


def _zincir_flush(zincir: str):
    """Belirtilen zincirdeki tüm kuralları temizle (zincirin kendisi kalır)."""
    _komut_calistir(
        ['nft', 'flush', 'chain', TABLO_AILE, TABLO_ADI, zincir],
        sessiz=True
    )


def _koruma_kurallarini_ekle() -> None:
    """
    Anti-lockout + loopback koruma kurallarını ekler. Bunlar zincirlerin EN
    ÜSTÜNE (kullanıcı kurallarından ÖNCE) eklenir, böylece bir kullanıcı DROP
    kuralı bunları override edemez.

    - Loopback (lo) her zaman serbest → yerel servisler bozulmaz.
    - Yönetim portları (panel + SSH) input'ta her zaman kabul → kullanıcı
      kendini panelden/SSH'tan kilitleyemez (BB_ANTI_LOCKOUT=1).

    flush'tan SONRA, kullanıcı kuralları uygulanmadan ÖNCE çağrılmalıdır
    (nft 'add rule' sona eklediği için ilk eklenenler en üstte kalır).
    """
    # Loopback trafiği koşulsuz serbest (input + output)
    _komut_calistir(['nft', 'add', 'rule', TABLO_AILE, TABLO_ADI, 'input', 'iif', 'lo', 'accept'], sessiz=True)
    _komut_calistir(['nft', 'add', 'rule', TABLO_AILE, TABLO_ADI, 'output', 'oif', 'lo', 'accept'], sessiz=True)

    # Anti-lockout: yönetim portlarına gelen erişimi her zaman kabul et
    if ANTI_LOCKOUT and YONETIM_PORTLARI:
        for port in YONETIM_PORTLARI:
            _komut_calistir(
                ['nft', 'add', 'rule', TABLO_AILE, TABLO_ADI, 'input', 'tcp', 'dport', port, 'accept'],
                sessiz=True
            )
        print(f"[nft] Anti-lockout aktif: yönetim portları {', '.join(YONETIM_PORTLARI)} input'ta korunuyor")


# ══════════════════════════════════════════════════════════════
#  KURAL DÖNÜŞTÜRME (DB row → nft args)
# ══════════════════════════════════════════════════════════════

def _kural_args_olustur(kural: dict[str, Any]) -> list[list[str]]:
    """
    DB'deki bir kural satırını nft komut argüman listelerine çevirir.

    Bir kural birden çok zincire uygulanabilir: yon='her' ise input + output +
    forward zincirlerinin ÜÇÜNE de eklenir. Böylece kullanıcı "bu IP'yi engelle"
    dediğinde hem firewall'ın kendi trafiği (output), hem arkasındaki istemciler
    (forward) engellenmiş olur — naif kullanıcı beklentisiyle uyumlu.

    Örnek dönüş (yon='her', hedef 8.8.8.8 engelle):
        [['nft','add','rule','inet','blackbarrier','input', 'ip','daddr','8.8.8.8','log','prefix','bb:42','drop','comment','bb:42'],
         ['nft','add','rule','inet','blackbarrier','output',...],
         ['nft','add','rule','inet','blackbarrier','forward',...]]

    Geçersiz/bilinmeyen yon-eylem → boş liste (kural atlanır).
    """
    yon_db = (kural.get('yon') or '').lower()
    if yon_db == 'her':
        zincirler = ['input', 'output', 'forward']
    else:
        z = ZINCIR_HARITASI.get(yon_db)
        if not z:
            return []
        zincirler = [z]

    eylem_db = (kural.get('eylem') or '').lower()
    eylem = EYLEM_HARITASI.get(eylem_db)
    if not eylem:
        return []

    protokol = (kural.get('protokol') or 'herhangi').lower()

    # ── Zincir-bağımsız gövde: eşleşme + log + eylem ──────────
    govde: list[str] = []

    # IPv4 adres filtreleri (Pydantic IPv4 regex'i bu noktada geçmiş demektir)
    if kural.get('kaynak_ip'):
        govde += ['ip', 'saddr', str(kural['kaynak_ip'])]
    if kural.get('hedef_ip'):
        govde += ['ip', 'daddr', str(kural['hedef_ip'])]

    # Protokol + portlar.
    # ÖNEMLİ: portsuz tcp/udp'de 'tcp'/'udp' tek başına geçersiz nft sözdizimidir
    # (returncode!=0 → kural sessizce uygulanmaz). Portsuz durumda
    # 'ip protocol tcp/udp' kullanılır; portluda 'tcp dport N' vb.
    if protokol == 'tcp':
        if kural.get('kaynak_port') or kural.get('hedef_port'):
            govde += ['tcp']
            if kural.get('kaynak_port'):
                govde += ['sport', str(kural['kaynak_port'])]
            if kural.get('hedef_port'):
                govde += ['dport', str(kural['hedef_port'])]
        else:
            govde += ['ip', 'protocol', 'tcp']
    elif protokol == 'udp':
        if kural.get('kaynak_port') or kural.get('hedef_port'):
            govde += ['udp']
            if kural.get('kaynak_port'):
                govde += ['sport', str(kural['kaynak_port'])]
            if kural.get('hedef_port'):
                govde += ['dport', str(kural['hedef_port'])]
        else:
            govde += ['ip', 'protocol', 'udp']
    elif protokol == 'icmp':
        # nftables 'inet' ailesinde ICMPv4 için:
        govde += ['ip', 'protocol', 'icmp']
    # 'herhangi' → protokol filtresi yok (tüm protokoller engellenir/izin verilir)

    # Log prefix EYLEMDEN ÖNCE eklenir (nft syntax: ... log prefix "bb:N" drop).
    # KRİTİK: prefix/comment değerleri TIRNAK içinde olmalı. nft, 'log prefix'
    # ve 'comment' için QUOTED_STRING bekler; içinde ':' olan tırnaksız bir
    # token (bb:5) ayrıştırıcıda sözdizimi hatası verir ve TÜM kural reddedilir
    # (returncode≠0, sessizce) → engelleme hiç uygulanmaz. nft argv'yi tek
    # buffer'da birleştirip yeniden lexer'dan geçirdiği için gömülü tırnaklar
    # string sınırlayıcı olarak doğru yorumlanır.
    kid = kural.get('id')
    if kid is not None:
        govde += ['log', 'prefix', f'"bb:{kid}"']

    govde.append(eylem)

    # DB ID'sini comment olarak da ekle (debug / `nft list` çıktısında görmek için)
    if kid is not None:
        govde += ['comment', f'"bb:{kid}"']

    return [
        ['nft', 'add', 'rule', TABLO_AILE, TABLO_ADI, zincir] + govde
        for zincir in zincirler
    ]


# ══════════════════════════════════════════════════════════════
#  UYGULAMA API'Sİ
# ══════════════════════════════════════════════════════════════

def tum_kurallari_uygula(kurallar: Iterable[dict[str, Any]]) -> tuple[int, int]:
    """
    Verilen kuralları nftables'a uygular.

    Akış:
      1. Ortamı hazırla (tablo/zincir yoksa oluştur)
      2. input/forward/output zincirlerini flush et
      3. Yalnızca aktif kuralları öncelik sırasıyla insert et

    Döndürür: (başarılı_sayısı, başarısız_sayısı)
    """
    with _uygula_kilidi:
        _ortam_hazirla()

        for zincir in ZINCIR_HARITASI.values():
            _zincir_flush(zincir)

        # Koruma kuralları (loopback + anti-lockout) — kullanıcı kurallarından ÖNCE
        _koruma_kurallarini_ekle()

        siralanmis = sorted(
            (k for k in kurallar if int(k.get('aktif', 1) or 0) == 1),
            key=lambda k: (int(k.get('oncelik') or 100), int(k.get('id') or 0))
        )

        basarili = 0
        basarisiz = 0
        for k in siralanmis:
            komutlar = _kural_args_olustur(k)
            if not komutlar:
                basarisiz += 1
                print(f"[nft] Kural #{k.get('id')} çevrilemedi (geçersiz yon/eylem/protokol)")
                continue
            # Bir kural birden çok zincire uygulanabilir (yon='her' → 3 zincir)
            for args in komutlar:
                kod, _, _ = _komut_calistir(args)
                if kod == 0:
                    basarili += 1
                else:
                    basarisiz += 1

        print(f"[nft] {basarili} zincir kuralı uygulandı, {basarisiz} başarısız")

        # ── Trafik İzleme catch-all kuralları ─────────────────────
        # BB_TRAFIK_IZLEME=1 ise her zincirin SONUNA rate-limited log+accept
        # ekle. Kullanıcı kuralları yukarıda eşleşmediyse bu yakalar ve
        # bb:0 prefix'iyle kernel log'a yazar → log_toplayici'ye düşer.
        #
        # Subprocess list-args ile nft komutuna geçirirken:
        # - prefix argümanı BOŞLUKSUZ olmalı (yoksa shell olmadığı için
        #   nft parser onu farklı tokenlara bölmez ama 'bb:0 ' (trailing
        #   space) bazı nft sürümlerinde reddediliyor)
        # - 'comment' parametresi kaldırıldı; bazı Ubuntu 24.04 nft
        #   sürümlerinde subprocess list-args ile sözdizimi sorunu çıkarıyor
        if TRAFIK_IZLEME:
            izleme_kural_sayisi = 0
            for zincir in ZINCIR_HARITASI.values():
                args = [
                    'nft', 'add', 'rule', TABLO_AILE, TABLO_ADI, zincir,
                    'limit', 'rate', TRAFIK_IZLEME_RATE,
                    'log', 'prefix', '"bb:0"',
                    'accept',
                ]
                kod, _, stderr = _komut_calistir(args)
                if kod == 0:
                    izleme_kural_sayisi += 1
                else:
                    print(f"[nft] izleme kuralı '{zincir}' chain'ine eklenemedi: {stderr.strip()}")
            print(f"[nft] Trafik izleme aktif: {izleme_kural_sayisi}/3 chain'e catch-all log eklendi (rate={TRAFIK_IZLEME_RATE})")

        return basarili, basarisiz


def firewall_durdur() -> bool:
    """
    Güvenlik duvarını 'devre dışı' bırak: 3 filter zincirini de flush et.
    Zincirlerin policy'si 'accept' olduğu için trafik serbestçe akar.
    Tablo ve zincirler korunur ki tekrar baslat()'ta sorun çıkmasın.
    """
    with _uygula_kilidi:
        _ortam_hazirla()
        for zincir in ZINCIR_HARITASI.values():
            _zincir_flush(zincir)
        print("[nft] Filter zincirleri temizlendi (firewall durdu)")
        return True


def firewall_baslat(
    kurallar: Iterable[dict[str, Any]],
    yonlendirme_kurallari: Iterable[dict[str, Any]] | None = None,
) -> tuple[int, int]:
    """
    Güvenlik duvarını yeniden başlat: DB'deki aktif filter kurallarını
    ve (verilmişse) yönlendirme kurallarını uygula.
    """
    sonuc = tum_kurallari_uygula(kurallar)
    if yonlendirme_kurallari is not None:
        tum_yonlendirme_kurallarini_uygula(yonlendirme_kurallari)
    print("[nft] Güvenlik duvarı yeniden başlatıldı")
    return sonuc


# ══════════════════════════════════════════════════════════════
#  NAT / YÖNLENDİRME (DNAT / SNAT / MASQUERADE)
# ══════════════════════════════════════════════════════════════

def _nat_ortam_hazirla() -> None:
    """
    bb_nat tablosu ve app-yönetimli zincirler yoksa oluştur. Idempotent.

    install.sh'in default 'postrouting' zincirine dokunmaz; o priority 100'de
    LAN→WAN için fallback masquerade sağlamaya devam eder.
    """
    _komut_calistir(['nft', 'add', 'table', 'ip', NAT_TABLO_ADI], sessiz=True)

    pre_tanim = '{ type nat hook prerouting priority -100 ; policy accept ; }'
    post_tanim = '{ type nat hook postrouting priority 90 ; policy accept ; }'

    _komut_calistir(
        ['nft', 'add', 'chain', 'ip', NAT_TABLO_ADI, NAT_PREROUTING_CHAIN, pre_tanim],
        sessiz=True
    )
    _komut_calistir(
        ['nft', 'add', 'chain', 'ip', NAT_TABLO_ADI, NAT_POSTROUTING_CHAIN, post_tanim],
        sessiz=True
    )


def _yonlendirme_args_olustur(kural: dict[str, Any]) -> list[str] | None:
    """
    DB yonlendirme_kurallari satırını nft komut argümanlarına çevirir.

    Tür eşlemeleri:
      - masquerade: oifname=<dis_arayuz> masquerade
                    → bb_app_postrouting
      - snat:       oifname=<dis_arayuz> snat to <ic_ip>
                    → bb_app_postrouting (ic_ip = yeni kaynak IP)
      - dnat:       iifname=<dis_arayuz> <protokol> dport <dis_port>
                    dnat to <ic_ip>[:<ic_port>]
                    → bb_app_prerouting (port forward)

    Geçersiz/eksik veri için None döner (kural atlanır).
    """
    tur = (kural.get('tur') or '').lower()
    protokol = (kural.get('protokol') or 'herhangi').lower()
    dis_arayuz = kural.get('dis_arayuz')

    if tur == 'masquerade':
        if not dis_arayuz:
            return None
        args = ['nft', 'add', 'rule', 'ip', NAT_TABLO_ADI, NAT_POSTROUTING_CHAIN,
                'oifname', str(dis_arayuz), 'masquerade']

    elif tur == 'snat':
        if not dis_arayuz or not kural.get('ic_ip'):
            return None
        args = ['nft', 'add', 'rule', 'ip', NAT_TABLO_ADI, NAT_POSTROUTING_CHAIN,
                'oifname', str(dis_arayuz),
                'snat', 'to', str(kural['ic_ip'])]

    elif tur == 'dnat':
        # DNAT'ta protokol zorunlu (herhangi olamaz, çünkü dport gerekli)
        if (not dis_arayuz or protokol not in ('tcp', 'udp')
                or not kural.get('dis_port') or not kural.get('ic_ip')):
            return None
        args = ['nft', 'add', 'rule', 'ip', NAT_TABLO_ADI, NAT_PREROUTING_CHAIN,
                'iifname', str(dis_arayuz),
                protokol, 'dport', str(kural['dis_port'])]
        hedef = str(kural['ic_ip'])
        if kural.get('ic_port'):
            hedef += f":{kural['ic_port']}"
        args += ['dnat', 'to', hedef]

    else:
        return None

    kid = kural.get('id')
    if kid is not None:
        # comment değeri tırnaklı olmalı (':' içerir) — bkz. _kural_args_olustur notu
        args += ['comment', f'"bb:{kid}"']

    return args


def tum_yonlendirme_kurallarini_uygula(
    kurallar: Iterable[dict[str, Any]]
) -> tuple[int, int]:
    """
    Tüm aktif yönlendirme/NAT kurallarını nftables'a uygular.

    Strateji: app-yönetimli prerouting/postrouting zincirlerini flush et,
    DB'deki aktif kuralları öncelik/id sırasıyla yeniden ekle.
    install.sh'in default 'postrouting' zincirine dokunulmaz.

    Döndürür: (başarılı_sayısı, başarısız_sayısı)
    """
    with _uygula_kilidi:
        _nat_ortam_hazirla()

        _komut_calistir(
            ['nft', 'flush', 'chain', 'ip', NAT_TABLO_ADI, NAT_PREROUTING_CHAIN],
            sessiz=True
        )
        _komut_calistir(
            ['nft', 'flush', 'chain', 'ip', NAT_TABLO_ADI, NAT_POSTROUTING_CHAIN],
            sessiz=True
        )

        aktif_kurallar = sorted(
            (k for k in kurallar if int(k.get('aktif', 1) or 0) == 1),
            key=lambda k: int(k.get('id') or 0)
        )

        basarili = 0
        basarisiz = 0
        for k in aktif_kurallar:
            args = _yonlendirme_args_olustur(k)
            if not args:
                basarisiz += 1
                print(f"[nft-nat] Yönlendirme #{k.get('id')} çevrilemedi "
                      f"(eksik/geçersiz alan: tur={k.get('tur')}, "
                      f"protokol={k.get('protokol')})")
                continue
            kod, _, _ = _komut_calistir(args)
            if kod == 0:
                basarili += 1
            else:
                basarisiz += 1

        print(f"[nft-nat] {basarili} yönlendirme uygulandı, {basarisiz} başarısız")
        return basarili, basarisiz
