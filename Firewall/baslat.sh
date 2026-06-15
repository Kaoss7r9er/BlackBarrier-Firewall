#!/bin/bash
# Black Barrier - Güvenli Başlatma ve Loglayıcı
# Bu script, firewall'ı manuel olarak başlattığınızda çalıştırılmalıdır.

echo "==============================================="
echo "   BLACK BARRIER FIREWALL BAŞLATMA ARACI       "
echo "==============================================="
echo ""

# Yöneticiye başlatma sebebini sor
echo "Lütfen firewall'ın neden başlatıldığını veya yeniden başlatıldığını açıklayın:"
echo "(Örn: Elektrik kesintisi, Güncelleme sonrası reboot, Kurulum vb.)"
read -p "> " ACIKLAMA

if [ -z "$ACIKLAMA" ]; then
    ACIKLAMA="Belirtilmedi (Boş girildi)"
fi

echo ""
echo "[*] Neden kaydediliyor..."

# Uvicorn başlatılmadan önce veritabanına doğrudan kayıt atabilmek için küçük bir Python kodu çalıştırıyoruz
python3 -c "
import sqlite3, sys, os
from datetime import datetime

# db_yonetici.py ile aynı klasördeki DB'yi bul
# Bash script'inin çalıştırıldığı dizini (proje kök dizini) al
base_dir = os.getcwd()
db_path = os.path.join(base_dir, 'veritabani', 'blackbarrier.db')

try:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Tablo var mı diye kontrol etmiyoruz, çünkü main.py ilk çalışmada oluşturur
    # Fakat ilk çalışma öncesiyse tablo oluşturulmamış olabilir.
    cur.execute('''CREATE TABLE IF NOT EXISTS sistem_loglari (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    olay_turu TEXT NOT NULL,
                    aciklama TEXT NOT NULL,
                    zaman TEXT NOT NULL DEFAULT (datetime('now'))
                )''')
    cur.execute('INSERT INTO sistem_loglari (olay_turu, aciklama) VALUES (?, ?)', ('yeniden_baslatma', sys.argv[1]))
    conn.commit()
    conn.close()
    print('[-] Log veritabanına işlendi.')
except Exception as e:
    print(f'[!] Log yazılamadı: {e} (DB Yolu: {db_path})')
" "$ACIKLAMA"

echo "[*] Black Barrier Core Başlatılıyor (Uvicorn)..."
echo "Çıkış yapmak için CTRL+C tuşlarına basın."
echo "==============================================="

# Uvicorn komutu bulunamazsa diye doğrudan python modülü üzerinden çağırıyoruz
python3 -m uvicorn modül.main:app --host 0.0.0.0 --port 8000
