import { defineConfig } from "vite";

// https://vitejs.dev/config
export default defineConfig({
  root: "src/renderer",
  base: "/",
  publicDir: "src/renderer/assets",
  build: {
    outDir: "../../../.vite/renderer/main_window",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: "src/renderer/views/index.html",
        chat: "src/renderer/views/chat.html",
      },
    },
  },
});
