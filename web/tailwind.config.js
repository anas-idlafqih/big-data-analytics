const c = (v) => `rgb(var(--${v}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: c("bg"), surface: c("surface"), elevated: c("elevated"),
        ink: c("ink"), muted: c("muted"), line: c("line"),
        accent: c("accent"), accent2: c("accent2"),
        good: c("good"), bad: c("bad"), warn: c("warn"),
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgb(var(--accent) / .35), 0 8px 40px -8px rgb(var(--accent) / .35)",
        card: "0 1px 0 0 rgb(255 255 255 / .04) inset, 0 12px 32px -16px rgb(0 0 0 / .45)",
      },
      keyframes: {
        shimmer: { "100%": { transform: "translateX(100%)" } },
        float: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-8px)" } },
        blink: { "50%": { opacity: "0" } },
      },
      animation: {
        shimmer: "shimmer 1.6s infinite",
        float: "float 8s ease-in-out infinite",
        blink: "blink 1s steps(1) infinite",
      },
    },
  },
  plugins: [],
};
