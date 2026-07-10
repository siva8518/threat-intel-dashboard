/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Enterprise-SaaS dark palette: near-black base with a faint blue-violet
        // undertone (not flat black) so glass panels have something to refract.
        background: "#05060a",
        surface: "#0d0f1a",
        "surface-hover": "#141729",
        border: "#232841",
        foreground: "#eef0fa",
        muted: "#8d93ac",
        primary: {
          DEFAULT: "#6d5bff",
          foreground: "#ffffff",
        },
        accent: {
          cyan: "#22d3ee",
          violet: "#a855f7",
          blue: "#3b82f6",
        },
        critical: "#fb3f5e",
        high: "#f7913d",
        medium: "#f2c94c",
        low: "#2fd97c",
        info: "#3b82f6",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      backgroundImage: {
        "gradient-mesh":
          "radial-gradient(at 15% 0%, rgba(109,91,255,0.16) 0px, transparent 55%), radial-gradient(at 85% 8%, rgba(34,211,238,0.12) 0px, transparent 50%), radial-gradient(at 50% 100%, rgba(168,85,247,0.10) 0px, transparent 55%)",
        "gradient-primary": "linear-gradient(135deg, #6d5bff 0%, #a855f7 100%)",
        "gradient-accent": "linear-gradient(135deg, #22d3ee 0%, #3b82f6 100%)",
        "gradient-critical": "linear-gradient(135deg, #fb3f5e 0%, #f7913d 100%)",
        shimmer: "linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent)",
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(0 0 0 / 0.3)",
        glass: "0 8px 32px -8px rgba(0,0,0,0.45), inset 0 1px 0 0 rgba(255,255,255,0.04)",
        "glow-primary": "0 0 0 1px rgba(109,91,255,0.35), 0 8px 24px -4px rgba(109,91,255,0.35)",
        "glow-cyan": "0 0 0 1px rgba(34,211,238,0.3), 0 8px 24px -4px rgba(34,211,238,0.3)",
        popover: "0 16px 48px -12px rgba(0,0,0,0.6)",
      },
      borderRadius: {
        lg: "1rem",
        md: "0.75rem",
        sm: "0.5rem",
        xl: "1.25rem",
        "2xl": "1.75rem",
      },
      keyframes: {
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        "fade-in": {
          from: { opacity: 0 },
          to: { opacity: 1 },
        },
      },
      animation: {
        shimmer: "shimmer 1.8s ease-in-out infinite",
        "fade-in": "fade-in 0.2s ease-out",
      },
    },
  },
  plugins: [],
};
