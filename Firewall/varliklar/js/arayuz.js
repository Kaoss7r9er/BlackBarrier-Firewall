/**
 * Black Barrier - Ortak Arayüz Etkileşim Kodları (UI Scripts)
 * Profil menüsü tıkla/aç veya üzerine gel/aç (hover) etkinlikleri için.
 */

document.addEventListener('DOMContentLoaded', () => {

    // Profil Menüsü (Tıklama ile Açılma/Kapanma Mantığı)
    const profilButonu = document.getElementById('profilButonu');
    const profilMenusu = document.getElementById('profilMenusu');

    if (profilButonu && profilMenusu) {
        // Butona tıklandığında (veya hover alternatifi olarak)
        profilButonu.addEventListener('click', (e) => {
            e.stopPropagation(); // Olayın body'e yayılmasını engelle
            profilMenusu.classList.toggle('hidden');
        });

        // Menü dışına (body) tıklandığında menüyü kapat
        document.addEventListener('click', (e) => {
            if (!profilMenusu.contains(e.target) && !profilButonu.contains(e.target)) {
                profilMenusu.classList.add('hidden');
            }
        });

        // Menünün içindeyken tıklamaların menüyü kapatmasını engelle
        profilMenusu.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }

});
