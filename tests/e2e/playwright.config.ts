import { defineConfig } from "@playwright/test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(__dirname, "../..");
const work = mkdtempSync(join(tmpdir(), "scradar-e2e-"));
const py = process.env.SCRADAR_PYTHON ?? (process.platform === "win32" ? join(root, ".venv/Scripts/python.exe") : "python");
const PORT = 8123;

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  timeout: 90_000,
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    channel: process.env.E2E_CHANNEL || undefined, // e.g. "msedge" locally; CI installs chromium
    viewport: { width: 1360, height: 900 },
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
  },
  webServer: {
    command: `"${py}" -c "from scradar.cli.main import app; app(['serve','--port','${PORT}'])"`,
    url: `http://127.0.0.1:${PORT}/api/v1/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      SCRADAR_DATABASE_URL: `sqlite:///${join(work, "e2e.db").replace(/\\/g, "/")}`,
      SCRADAR_CACHE_DIR: join(work, "cache"),
      SCRADAR_STATIC_DIR: join(root, "frontend/dist"),
      SCRADAR_EXAMPLES_DIR: root,
      // Unreachable on purpose: proves a provider outage never turns into a fabricated "clean" result.
      SCRADAR_OSV_URL: "http://127.0.0.1:9",
    },
  },
});
