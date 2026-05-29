import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

/** A table row streamed from the backend (mirrors the Rust `ScanRow`). */
interface ScanRow {
  index: number;
  proxy: string;
  username: string | null;
  password: string | null;
  protocol: string | null;
  alive: boolean;
  exit_ip: string | null;
  country_code: string | null;
  country_name: string | null;
  region: string | null;
  connect_ms: number | null;
  rtt_ms: number | null;
  anonymity: string | null;
  rotation: string | null;
  observed_ips: number;
  error: string | null;
}

interface StartedPayload {
  total: number;
  skipped: number;
}
interface ProgressPayload {
  done: number;
  total: number;
}

type ColumnKey =
  | "proxy"
  | "protocol"
  | "alive"
  | "exit_ip"
  | "country"
  | "ping"
  | "anonymity"
  | "rotation";

interface Column {
  key: ColumnKey;
  label: string;
  /** Value used for sorting; numbers sort numerically, strings lexically. */
  sortValue: (row: ScanRow) => string | number;
}

const COLUMNS: Column[] = [
  { key: "proxy", label: "Proxy", sortValue: (r) => r.proxy },
  { key: "protocol", label: "Type", sortValue: (r) => r.protocol ?? "" },
  { key: "alive", label: "Status", sortValue: (r) => (r.alive ? 1 : 0) },
  { key: "exit_ip", label: "Exit IP", sortValue: (r) => r.exit_ip ?? "" },
  { key: "country", label: "Country", sortValue: (r) => r.country_code ?? r.country_name ?? "" },
  { key: "ping", label: "Ping (ms)", sortValue: (r) => r.rtt_ms ?? Number.MAX_SAFE_INTEGER },
  { key: "anonymity", label: "Anonymity", sortValue: (r) => r.anonymity ?? "" },
  { key: "rotation", label: "Rotation", sortValue: (r) => r.rotation ?? "" },
];

/** Mutable UI state. */
const state = {
  rows: new Map<number, ScanRow>(),
  total: 0,
  done: 0,
  scanning: false,
  filterText: "",
  statusFilter: "all" as "all" | "alive" | "dead",
  sortKey: "proxy" as ColumnKey,
  sortDir: "asc" as "asc" | "desc",
  selected: new Set<number>(),
};

/** Proxy export/copy formats, keyed by the `<select id="proxy-format">` value. */
type ProxyFormat = "hostport" | "hostportauth" | "scheme" | "authhost";

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
}

/** Persisted user settings (mirrors the optional fields of Rust `ScanRequest`). */
interface Settings {
  judge_url: string;
  concurrency: number;
  connect_timeout_secs: number;
  request_timeout_secs: number;
  geolite_path: string;
  allow_http_geoip: boolean;
}

const SETTINGS_KEY = "proxyscope.settings";

const SETTINGS_FIELDS: Array<{
  id: string;
  key: keyof Settings;
  kind: "text" | "number" | "checkbox";
}> = [
  { id: "set-judge", key: "judge_url", kind: "text" },
  { id: "set-concurrency", key: "concurrency", kind: "number" },
  { id: "set-connect", key: "connect_timeout_secs", kind: "number" },
  { id: "set-request", key: "request_timeout_secs", kind: "number" },
  { id: "set-geolite", key: "geolite_path", kind: "text" },
  { id: "set-http-geoip", key: "allow_http_geoip", kind: "checkbox" },
];

function readSettings(): Settings {
  const settings = {} as Settings;
  for (const field of SETTINGS_FIELDS) {
    const el = $<HTMLInputElement>(field.id);
    if (field.kind === "checkbox") {
      (settings[field.key] as boolean) = el.checked;
    } else if (field.kind === "number") {
      (settings[field.key] as number) = Number(el.value);
    } else {
      (settings[field.key] as string) = el.value.trim();
    }
  }
  return settings;
}

function loadSettings(): void {
  let stored: Partial<Settings> = {};
  try {
    stored = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? "{}");
  } catch {
    stored = {};
  }
  for (const field of SETTINGS_FIELDS) {
    const el = $<HTMLInputElement>(field.id);
    const value = stored[field.key];
    if (value != null) {
      if (field.kind === "checkbox") {
        el.checked = Boolean(value);
      } else {
        el.value = String(value);
      }
    }
    el.addEventListener("change", saveSettings);
  }
}

function saveSettings(): void {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(readSettings()));
}

/** Escapes text for safe insertion into innerHTML. */
function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function countryText(row: ScanRow): string {
  const parts = [row.country_code ?? row.country_name, row.region].filter(Boolean);
  return parts.join(" · ");
}

function visibleRows(): ScanRow[] {
  const text = state.filterText.trim().toLowerCase();
  const rows = [...state.rows.values()].filter((row) => {
    if (state.statusFilter === "alive" && !row.alive) return false;
    if (state.statusFilter === "dead" && row.alive) return false;
    if (!text) return true;
    const haystack = [row.proxy, row.exit_ip, row.country_code, row.country_name]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.includes(text);
  });

  const column = COLUMNS.find((c) => c.key === state.sortKey) ?? COLUMNS[0];
  const dir = state.sortDir === "asc" ? 1 : -1;
  rows.sort((a, b) => {
    const av = column.sortValue(a);
    const bv = column.sortValue(b);
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    return (a.index - b.index) * dir;
  });
  return rows;
}

function headHtml(): string {
  const selectTh = `<th class="col-select"><input type="checkbox" id="select-all" title="Select all (filtered)" /></th>`;
  const cols = COLUMNS.map((col) => {
    const active = col.key === state.sortKey;
    const arrow = active ? (state.sortDir === "asc" ? " ▲" : " ▼") : "";
    return `<th data-key="${col.key}" class="${active ? "sorted" : ""}">${esc(col.label)}${arrow}</th>`;
  }).join("");
  return selectTh + cols;
}

function rowHtml(row: ScanRow): string {
  const status = row.alive
    ? `<span class="badge badge--ok">alive</span>`
    : `<span class="badge badge--dead" title="${esc(row.error ?? "")}">dead</span>`;
  const ping =
    row.rtt_ms != null
      ? `<span title="connect ${row.connect_ms ?? "?"} ms">${row.rtt_ms}</span>`
      : "—";
  const rotation =
    row.rotation && row.rotation !== "unknown"
      ? `${esc(row.rotation)}${row.observed_ips > 1 ? ` (${row.observed_ips})` : ""}`
      : "—";
  const checked = state.selected.has(row.index) ? "checked" : "";

  return `<tr class="${row.alive ? "" : "row--dead"}">
    <td class="col-select"><input type="checkbox" class="row-select" data-index="${row.index}" ${checked} /></td>
    <td class="mono">${esc(row.proxy)}</td>
    <td>${esc(row.protocol ?? "—")}</td>
    <td>${status}</td>
    <td class="mono">${esc(row.exit_ip ?? "—")}</td>
    <td>${esc(countryText(row) || "—")}</td>
    <td class="num">${ping}</td>
    <td>${esc(row.anonymity ?? "—")}</td>
    <td>${rotation}</td>
  </tr>`;
}

let renderQueued = false;
function render(): void {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    const rows = visibleRows();
    $("head-row").innerHTML = headHtml();
    $("rows").innerHTML = rows.map(rowHtml).join("");
    $("empty").hidden = state.rows.size > 0;

    // Reflect selection state on the header "select all" checkbox.
    const selectedVisible = rows.filter((r) => state.selected.has(r.index)).length;
    const selectAll = document.getElementById("select-all") as HTMLInputElement | null;
    if (selectAll) {
      selectAll.checked = rows.length > 0 && selectedVisible === rows.length;
      selectAll.indeterminate = selectedVisible > 0 && selectedVisible < rows.length;
    }

    const alive = [...state.rows.values()].filter((r) => r.alive).length;
    $("counts").textContent = `${rows.length} shown · ${alive} alive · ${state.rows.size} total`;
    $("select-info").textContent = state.selected.size > 0 ? `${state.selected.size} selected` : "";
  });
}

function selectedRows(): ScanRow[] {
  return [...state.rows.values()]
    .filter((row) => state.selected.has(row.index))
    .sort((a, b) => a.index - b.index);
}

function aliveRows(): ScanRow[] {
  return [...state.rows.values()]
    .filter((row) => row.alive)
    .sort((a, b) => a.index - b.index);
}

/** Renders one proxy in the chosen export format. */
function formatProxy(row: ScanRow, format: ProxyFormat): string {
  const auth = row.username ? `${row.username}:${row.password ?? ""}` : "";
  switch (format) {
    case "hostportauth":
      return auth ? `${row.proxy}:${auth}` : row.proxy;
    case "scheme": {
      const scheme = row.protocol && row.protocol !== "mtproxy" ? row.protocol : "http";
      return auth ? `${scheme}://${auth}@${row.proxy}` : `${scheme}://${row.proxy}`;
    }
    case "authhost":
      return auth ? `${auth}@${row.proxy}` : row.proxy;
    case "hostport":
    default:
      return row.proxy;
  }
}

function formatList(rows: ScanRow[], format: ProxyFormat): string {
  return rows.map((row) => formatProxy(row, format)).join("\n");
}

function currentFormat(): ProxyFormat {
  return $<HTMLSelectElement>("proxy-format").value as ProxyFormat;
}

/** Copies text to the clipboard, falling back to a hidden textarea. */
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

async function copySelected(): Promise<void> {
  const rows = selectedRows();
  if (rows.length === 0) {
    $("status").textContent = "No proxies selected.";
    return;
  }
  const ok = await copyText(formatList(rows, currentFormat()));
  $("status").textContent = ok
    ? `Copied ${rows.length} prox${rows.length === 1 ? "y" : "ies"} to clipboard.`
    : "Copy failed — clipboard unavailable.";
}

function exportSelected(): void {
  const rows = selectedRows();
  if (rows.length === 0) {
    $("status").textContent = "No proxies selected.";
    return;
  }
  download("proxyscope-selected.txt", "text/plain", formatList(rows, currentFormat()));
}

function exportAlive(): void {
  const rows = aliveRows();
  if (rows.length === 0) {
    $("status").textContent = "No alive proxies to export.";
    return;
  }
  download("proxyscope-alive.txt", "text/plain", formatList(rows, currentFormat()));
}

function setProgress(done: number, total: number): void {
  state.done = done;
  state.total = total;
  const wrap = $("progress-wrap");
  wrap.hidden = total === 0;
  const pct = total === 0 ? 0 : Math.round((done / total) * 100);
  $<HTMLDivElement>("progress-bar").style.width = `${pct}%`;
  $("status").textContent = state.scanning
    ? `Checking ${done}/${total}…`
    : total > 0
      ? `Done: ${done}/${total} checked`
      : "";
}

async function startScan(): Promise<void> {
  if (state.scanning) return;
  const text = $<HTMLTextAreaElement>("input").value;
  if (!text.trim()) {
    $("status").textContent = "Nothing to check — paste some proxies first.";
    return;
  }

  state.rows.clear();
  state.selected.clear();
  state.done = 0;
  state.scanning = true;
  render();

  const options = {
    check_rotation: $<HTMLInputElement>("rotation").checked,
    rotation_samples: Number($<HTMLInputElement>("samples").value) || 4,
    ...readSettings(),
  };
  saveSettings();

  try {
    const total = await invoke<number>("start_scan", { text, options });
    state.total = total;
    setProgress(0, total);
    if (total === 0) {
      state.scanning = false;
      $("status").textContent = "No valid proxies found in the input.";
    }
  } catch (err) {
    state.scanning = false;
    $("status").textContent = `Failed to start scan: ${String(err)}`;
  }
}

function download(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function exportCsv(): void {
  const header = [
    "proxy",
    "username",
    "password",
    "protocol",
    "alive",
    "exit_ip",
    "country_code",
    "country_name",
    "region",
    "connect_ms",
    "rtt_ms",
    "anonymity",
    "rotation",
    "observed_ips",
    "error",
  ];
  const cell = (value: unknown): string => {
    const text = value == null ? "" : String(value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  const lines = [header.join(",")];
  for (const row of visibleRows()) {
    lines.push(
      [
        row.proxy,
        row.username,
        row.password,
        row.protocol,
        row.alive,
        row.exit_ip,
        row.country_code,
        row.country_name,
        row.region,
        row.connect_ms,
        row.rtt_ms,
        row.anonymity,
        row.rotation,
        row.observed_ips,
        row.error,
      ]
        .map(cell)
        .join(","),
    );
  }
  download("proxyscope-results.csv", "text/csv", lines.join("\n"));
}

function exportJson(): void {
  download(
    "proxyscope-results.json",
    "application/json",
    JSON.stringify(visibleRows(), null, 2),
  );
}

async function setupEvents(): Promise<void> {
  await listen<StartedPayload>("scan-started", (event) => {
    setProgress(0, event.payload.total);
    const { skipped } = event.payload;
    if (skipped > 0) {
      $("status").textContent = `Checking ${event.payload.total}… (${skipped} unparsable line(s) skipped)`;
    }
  });

  await listen<ScanRow>("scan-result", (event) => {
    state.rows.set(event.payload.index, event.payload);
    render();
  });

  await listen<ProgressPayload>("scan-progress", (event) => {
    setProgress(event.payload.done, event.payload.total);
  });

  await listen<{ total: number }>("scan-finished", () => {
    state.scanning = false;
    setProgress(state.done || state.total, state.total);
    render();
  });
}

async function showCoreVersion(): Promise<void> {
  const el = $("core-version");
  try {
    el.textContent = `core v${await invoke<string>("app_version")}`;
  } catch (err) {
    el.textContent = "backend unavailable";
    console.error("app_version failed:", err);
  }
}

function wireControls(): void {
  $("start").addEventListener("click", () => void startScan());
  $("export-csv").addEventListener("click", exportCsv);
  $("export-json").addEventListener("click", exportJson);
  $("copy-selected").addEventListener("click", () => void copySelected());
  $("export-selected").addEventListener("click", exportSelected);
  $("export-alive").addEventListener("click", exportAlive);

  $<HTMLInputElement>("filter").addEventListener("input", (e) => {
    state.filterText = (e.target as HTMLInputElement).value;
    render();
  });
  $<HTMLSelectElement>("status-filter").addEventListener("change", (e) => {
    state.statusFilter = (e.target as HTMLSelectElement).value as typeof state.statusFilter;
    render();
  });

  // Header is rebuilt on every render, so use delegation for sort + select-all.
  $("head-row").addEventListener("click", (e) => {
    const th = (e.target as HTMLElement).closest("th[data-key]");
    if (!th) return;
    const key = th.getAttribute("data-key") as ColumnKey;
    if (state.sortKey === key) {
      state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
    } else {
      state.sortKey = key;
      state.sortDir = "asc";
    }
    render();
  });
  $("head-row").addEventListener("change", (e) => {
    const target = e.target as HTMLInputElement;
    if (target.id !== "select-all") return;
    for (const row of visibleRows()) {
      if (target.checked) state.selected.add(row.index);
      else state.selected.delete(row.index);
    }
    render();
  });

  // Row checkboxes are recreated on every render — delegate from the tbody.
  $("rows").addEventListener("change", (e) => {
    const target = e.target as HTMLInputElement;
    if (!target.classList.contains("row-select")) return;
    const index = Number(target.dataset.index);
    if (target.checked) state.selected.add(index);
    else state.selected.delete(index);
    render();
  });

  $<HTMLInputElement>("file").addEventListener("change", async (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    $<HTMLTextAreaElement>("input").value = await file.text();
    $("status").textContent = `Loaded ${file.name}`;
  });
}

window.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  wireControls();
  render();
  void showCoreVersion();
  void setupEvents();
});
