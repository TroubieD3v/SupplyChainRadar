import { expect, test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

// Generates the README screenshots from the real UI running on the real API (demo data is labelled as such).
const OUT = resolve(__dirname, "../../docs/screenshots");
mkdirSync(OUT, { recursive: true });

test("capture screenshots", async ({ page }) => {
  test.skip(!process.env.CAPTURE, "set CAPTURE=1 to regenerate docs/screenshots");
  await page.goto("/");
  await page.getByRole("button", { name: "Load demo data" }).click();
  await expect(page.getByRole("heading", { name: /Demo · / }).first()).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(2500);
  // Pick the npm storefront project with all three scans.
  await page.getByLabel("Project").selectOption({ label: "Demo · npm storefront" });
  await page.waitForTimeout(800);
  const options = await page.getByLabel("Scan").locator("option").allTextContents();
  const latest = options.findIndex((t) => t.startsWith("release 1.1"));
  if (latest >= 0) await page.getByLabel("Scan").selectOption({ index: latest });
  await page.waitForTimeout(1200);
  await page.screenshot({ path: `${OUT}/overview-dark.png` });

  await page.getByRole("button", { name: /Switch to light theme/ }).click();
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${OUT}/overview-light.png` });
  await page.getByRole("button", { name: /Switch to dark theme/ }).click();

  await page.getByLabel("Scan").selectOption({ index: options.findIndex((t) => t.startsWith("release 1.0 ·")) });
  await page.getByRole("link", { name: "Findings" }).first().click();
  await page.getByRole("button", { name: /demo-vulnerable-lib/ }).click();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/finding-detail.png` });
  await page.keyboard.press("Escape");

  await page.getByRole("link", { name: "Dependency Graph" }).first().click();
  await page.locator(".react-flow__node", { hasText: "demo-vulnerable-lib" }).click();
  await page.waitForTimeout(900);
  await page.screenshot({ path: `${OUT}/graph.png` });

  await page.getByRole("link", { name: "Remediation Studio" }).first().click();
  await page.getByLabel("Package").first().selectOption({ index: 1 });
  await page.waitForTimeout(300);
  const pkgs = await page.getByLabel("Package").first().locator("option").allTextContents();
  const parserIdx = pkgs.findIndex((t) => t.startsWith("demo-parser"));
  await page.getByLabel("Package").first().selectOption({ index: parserIdx });
  await page.getByLabel("Target version").fill("0.9.3");
  await page.getByRole("button", { name: "Simulate" }).click();
  await expect(page.getByText("Predicted (partial)").first()).toBeVisible();
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${OUT}/remediation.png`, fullPage: false });

  await page.getByLabel("Scan").selectOption({ index: options.findIndex((t) => t.startsWith("release 1.1")) });
  await page.getByRole("link", { name: "Compare & Timeline" }).first().click();
  await page.waitForTimeout(1500);
  await page.screenshot({ path: `${OUT}/compare.png` });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("navigation", { name: "Primary mobile" }).getByRole("link", { name: "Overview" }).click();
  await page.waitForTimeout(1200);
  await page.screenshot({ path: `${OUT}/mobile-overview.png` });
});
