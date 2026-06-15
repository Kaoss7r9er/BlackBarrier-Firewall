tailwind.config = {
    darkMode: "class",
    theme: {
        extend: {
            colors: {
                // Ana renk artık CSS değişkeninden gelir → kullanıcı "Tema Rengi"ni
                // ayarlardan değiştirince tüm panel canlı güncellenir. rgb(var/<alpha-value>)
                // deseni sayesinde bg-birincil/10 gibi opaklık modifiyeleri çalışmaya devam eder.
                "birincil":       "rgb(var(--bb-birincil-rgb, 37 99 235) / <alpha-value>)",       // Varsayılan: Blue 600
                "birincil-acik":  "rgb(var(--bb-birincil-acik-rgb, 59 130 246) / <alpha-value>)", // Blue 500
                "birincil-koyu":  "rgb(var(--bb-birincil-koyu-rgb, 29 78 216) / <alpha-value>)",  // Blue 700
                "birincil-soluk": "rgb(var(--bb-birincil-soluk-rgb, 239 246 255) / <alpha-value>)",// Blue 50
                "arkaplan-acik":  "#F8FAFC",       // Slate 50 — Hafif arka plan
                "arkaplan-koyu":  "#0F172A",       // Slate 900 — Koyu tema
                "yuzey":          "#FFFFFF",        // Beyaz yüzey
                "yuzey-vurgu":    "#F1F5F9",       // Slate 100
                "kenarlik":       "#E2E8F0",       // Slate 200 — Tek kenar rengi
                "kenarlik-koyu":  "#CBD5E1",       // Slate 300
                "metin-birincil": "#0F172A",       // Slate 900
                "metin-ikincil":  "#64748B",       // Slate 500
                "metin-ucuncul":  "#94A3B8",       // Slate 400
                "durum-basarili": "#10B981",       // Emerald 500
                "durum-kritik":   "#EF4444",       // Red 500
                "durum-uyari":    "#F59E0B",       // Amber 500
                "durum-bilgi":    "#3B82F6",       // Blue 500
                "veri-cizgisi":   "#6366F1",       // Indigo 500
            },
            fontFamily: {
                "ekran": ["Inter", "system-ui", "sans-serif"],
                "kod":   ["JetBrains Mono", "monospace"],
                "sans":  ["Inter", "system-ui", "sans-serif"],
            },
            borderRadius: {
                "DEFAULT": "8px",
                "sm":  "4px",
                "md":  "8px",
                "lg":  "12px",
                "xl":  "16px",
                "2xl": "20px",
            },
            boxShadow: {
                "yumusak":    "0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)",
                "orta":       "0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -1px rgba(0,0,0,0.04)",
                "buyuk":      "0 10px 25px -3px rgba(0,0,0,0.08), 0 4px 6px -2px rgba(0,0,0,0.03)",
                "parlama-basarili": "0 0 12px rgba(16,185,129,0.3)",
                "parlama-kritik":   "0 0 12px rgba(239,68,68,0.3)",
                "parlama-uyari":    "0 0 12px rgba(245,158,11,0.3)",
            },
            fontSize: {
                "2xs": ["0.625rem", { lineHeight: "0.875rem" }],
            }
        },
    },
}
