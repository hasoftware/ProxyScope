import { invoke } from "@tauri-apps/api/core";

/**
 * Fetches the core library version from the Rust backend and renders it.
 * This doubles as a smoke test that the UI <-> backend bridge works.
 */
async function showCoreVersion(): Promise<void> {
  const el = document.querySelector<HTMLSpanElement>("#core-version");
  if (!el) return;

  try {
    const version = await invoke<string>("app_version");
    el.textContent = `core v${version}`;
  } catch (err) {
    el.textContent = "backend unavailable";
    console.error("Failed to invoke app_version:", err);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  void showCoreVersion();
});
