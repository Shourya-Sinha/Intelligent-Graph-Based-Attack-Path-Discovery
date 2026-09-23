/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html","./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0a1020",
        card: "#111a2f",
        brand: "#0ea5e9",
        accent: "#6366f1"
      },
      boxShadow: {
        glow: "0 0 30px rgba(14,165,233,0.35)"
      },
      animation: {
        float: "float 6s ease-in-out infinite",
        pulseglow: "pulseglow 2.5s ease-in-out infinite"
      },
      keyframes: {
        float: {"0%,100%": {transform:"translateY(0)"}, "50%": {transform:"translateY(-8px)"}},
        pulseglow: {"0%,100%": {boxShadow:"0 0 20px rgba(99,102,241,0.4)"}, "50%": {boxShadow:"0 0 40px rgba(14,165,233,0.6)"}}
      }
    }
  },
  plugins: []
}
