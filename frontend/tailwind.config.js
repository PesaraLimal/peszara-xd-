/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#080a0f",
          card: "#0f131a",
          border: "#1d2433",
          green: "#10b981",       // Neon green
          greenGlow: "#059669",
          yellow: "#eab308",      // Warnings
          red: "#ef4444",         // Alerts/Critical
          blue: "#3b82f6",        // Informational
          textPrimary: "#f3f4f6", // Bright text
          textSecondary: "#9ca3af" // Muted text
        }
      },
      fontFamily: {
        mono: ["Courier New", "Courier", "monospace"],
      }
    },
  },
  plugins: [],
};
