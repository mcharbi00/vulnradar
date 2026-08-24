/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        panel: "#0f1420",
        accent: "#22d3ee",
      },
    },
  },
  plugins: [],
};
