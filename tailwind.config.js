/** Build: npx tailwindcss@3.4.17 -c tailwind.config.js -i static/tailwind.input.css -o static/tailwind.css --minify */
module.exports = {
  content: ["./index.html", "./static/app.js"],
  theme: {
    extend: {
      fontFamily: { sans: ["Inter Variable", "Inter", "system-ui", "sans-serif"] },
      colors: { slate: { 950: "#0b0f19", 900: "#111827", 800: "#1f2937" } },
    },
  },
};
