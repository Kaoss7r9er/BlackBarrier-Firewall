tailwind.config = {
    darkMode: "class",
    theme: {
        extend: {
            colors: {
                "birincil": "#0F172A",          // primary (Slate 900) - Koyu lacivert/siyah
                "birincil-acik": "#334155",      // primary-light (Slate 700)
                "arkaplan-acik": "#F1F5F9",      // background-light (Slate 100)
                "arkaplan-koyu": "#0F172A",      // background-dark (Slate 900)
                "yuzey": "#FFFFFF",              // surface
                "yuzey-vurgu": "#F8FAFC",        // surface-highlight
                "kenarlik-kalin": "#334155",     // border-heavy
                "kenarlik-hafif": "#94A3B8",     // border-light
                "durum-basarili": "#00E676",     // status-success
                "durum-kritik": "#FF1744",       // status-critical
                "durum-uyari": "#FFC400",        // status-warning
                "veri-cizgisi": "#3B82F6",       // data-line (Mavi)
            },
            fontFamily: {
                "ekran": ["Space Grotesk", "sans-serif"], // display
                "kod": ["JetBrains Mono", "monospace"],   // mono
                "sans": ["Space Grotesk", "sans-serif"],
            },
            borderWidth: {
                '3': '3px',
                'p': '1px' // Performans line'lar için pixel borders
            },
            borderRadius: {
                "DEFAULT": "0px", // Endüstriyel tasarım için keskin hatlar
                "sm": "2px",
                "lg": "4px",
            },
            boxShadow: {
                'parlama-basarili': '0 0 8px #00E676', // glow-success
                'parlama-kritik': '0 0 8px #FF1744',   // glow-critical
                'parlama-uyari': '0 0 8px #FFC400',    // glow-warning
            }
        },
    },
}
