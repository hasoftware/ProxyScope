import { defineConfig } from "vite";

// Tauri reads the frontend from a fixed dev server port. `TAURI_DEV_HOST`
// is set by the Tauri CLI when developing against a physical device.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  // Prevent Vite from clearing the screen so Rust compiler output stays visible.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: "ws", host, port: 1421 }
      : undefined,
    watch: {
      // The Rust side is rebuilt by Tauri, not Vite.
      ignored: ["**/src-tauri/**"],
    },
  },
});
