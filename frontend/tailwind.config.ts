import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "Consolas", "monospace"],
      },
      colors: {
        canvas: "#090d16",
        surface: "#0f1623",
        elevated: "#161f30",
        subtle: "#111928",
        borderSubtle: "#1e293b",
        borderStrong: "#334155",
      },
    },
  },
  plugins: [],
};

export default config;
