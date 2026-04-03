/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        terminal: {
          base: "#0a0e14",
          panel: "#0d1117",
          panelAlt: "#080c11",
          success: "#4ade80",
          danger: "#f87171",
          warn: "#fbbf24",
          info: "#60a5fa",
          cyan: "#22d3ee",
          purple: "#c084fc",
          gray: "#6b7280",
          grayDark: "#374151"
        }
      },
      fontFamily: {
        pixel: ['"Press Start 2P"', "monospace"],
        mono: ['"IBM Plex Mono"', "monospace"]
      },
      keyframes: {
        fadeSlide: {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" }
        },
        blink: {
          "0%, 49%": { opacity: "1" },
          "50%, 100%": { opacity: "0" }
        },
        pulseGreen: {
          "0%, 100%": { boxShadow: "0 0 3px rgba(74, 222, 128, 0.6)" },
          "50%": { boxShadow: "0 0 10px rgba(74, 222, 128, 0.95)" }
        },
        pulseRed: {
          "0%, 100%": { boxShadow: "0 0 4px rgba(248, 113, 113, 0.28)" },
          "50%": { boxShadow: "0 0 16px rgba(248, 113, 113, 0.52)" }
        }
      },
      animation: {
        fadeSlide: "fadeSlide 240ms ease-out",
        blink: "blink 1s step-end infinite",
        pulseGreen: "pulseGreen 1.4s ease-in-out infinite",
        pulseRed: "pulseRed 1.8s ease-in-out infinite"
      },
      boxShadow: {
        panel: "0 0 0 1px rgba(34, 211, 238, 0.12), inset 0 1px 0 rgba(34, 211, 238, 0.04)",
        cyan: "0 0 0 1px rgba(34, 211, 238, 0.35)",
        success: "0 0 14px rgba(74, 222, 128, 0.24)",
        danger: "0 0 14px rgba(248, 113, 113, 0.22)"
      }
    }
  },
  plugins: []
};
