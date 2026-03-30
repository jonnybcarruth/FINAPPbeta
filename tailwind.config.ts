import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        "ios-blue": "#007AFF",
        "ios-blue-dark": "#0062CC",
        "ios-red": "#FF3B30",
        "ios-green": "#34C759",
        "ios-gray": "#8E8E93",
        // Keep for backward compat during transition
        "dindin-green": "#007AFF",
        "dindin-green-dark": "#0062CC",
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "SF Pro Display",
          "SF Pro Text",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
      },
    },
  },
  plugins: [],
};
export default config;
