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
          bg: "#0B0F17",         // Deep space dark
          card: "#121824",       // Core component backing
          border: "#1E293B",     // Subtle layout division
          text: "#E2E8F0",       // High contrast text
          muted: "#94A3B8",      // Low contrast details
          accent: "#06B6D4",     // Neon cyan glow
          green: "#10B981",      // Clear/Online state
          yellow: "#F59E0B",     // Medium warning
          red: "#EF4444",        // Critical alert
          purple: "#8B5CF6",     // MITRE tag
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'Outfit', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan': '0 0 15px rgba(6, 182, 212, 0.15)',
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.25)',
        'glow-green': '0 0 15px rgba(16, 185, 129, 0.2)',
      }
    },
  },
  plugins: [],
}
