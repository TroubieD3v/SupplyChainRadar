import { expect, test, type Locator, type Page } from "@playwright/test";
import { resolve } from "node:path";

const ROOT = resolve(__dirname, "../..");
const ex = (...p: string[]) => resolve(ROOT, "examples", ...p);

async function pick(sel: Locator, re: RegExp) {
  const opts = await sel.locator("option").evaluateAll((os) => os.map((o) => [(o as HTMLOptionElement).value, o.textContent ?? ""]));
  const hit = opts.find(([, t]) => re.test(t));
  if (!hit) throw new Error(`no option matches ${re}: ${JSON.stringify(opts)}`);
  await sel.selectOption(hit[0]);
}

async function importFile(page: Page, file: string, source: string, label: string) {
  await page.getByRole("link", { name: "Projects & Imports" }).first().click();
  await page.getByLabel("Choose dependency files").setInputFiles(file);
  await page.getByLabel("Advisory source").selectOption({ label: source });
  await page.getByLabel("Scan label (optional)").fill(label);
  await page.getByRole("button", { name: "Import and scan" }).click();
  await expect(page.getByRole("row", { name: new RegExp(label) }).getByText(/completed|partial|failed/)).toBeVisible({ timeout: 30_000 });
}

test.describe.serial("primary journey", () => {
  let page: Page;
  test.beforeAll(async ({ browser }) => {
    page = await (await browser.newContext()).newPage();
  });
  test.afterAll(async () => page.context().close());

  test("fresh install shows honest empty state in dark theme", async () => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Know what you depend on." })).toBeVisible();
    await expect(page.locator("html")).toHaveClass(/dark/);
    await expect(page.getByText("Demo data", { exact: true })).toHaveCount(0);
    await expect(page.getByText(/no placeholder numbers/)).toBeVisible();
  });

  test("create a project and import a lockfile against a frozen snapshot", async () => {
    await page.getByRole("link", { name: "Create a project" }).click();
    await page.getByLabel("Project name").fill("storefront");
    await page.getByRole("button", { name: "Create" }).click();
    await expect(page.getByRole("heading", { name: /Import into/ })).toContainText("storefront");
    await page.getByLabel("Choose dependency files").setInputFiles(ex("npm-vulnerable", "package-lock.json"));
    await expect(page.getByText("npm lockfile")).toBeVisible();
    await page.getByLabel("Advisory source").selectOption({ label: "Frozen snapshot · demo-2026-10-01 (2026-10-01)" });
    await expect(page.getByText("No network traffic")).toBeVisible();
    await page.getByLabel("Scan label (optional)").fill("release 1.0");
    await page.getByRole("button", { name: "Import and scan" }).click();
    await expect(page.getByRole("row", { name: /release 1.0/ }).getByText("completed")).toBeVisible({ timeout: 30_000 });
  });

  test("overview uses real scan data", async () => {
    await page.getByRole("link", { name: "Overview" }).first().click();
    await expect(page.getByRole("heading", { name: "storefront", level: 1 })).toBeVisible();
    await expect(page.getByText("3 confirmed advisories across 9 packages")).toBeVisible();
    await page.getByRole("button", { name: /1 critical advisories/ }).click();
    await expect(page).toHaveURL(/findings\?severity=critical/);
    await expect(page.getByRole("button", { name: /demo-glob/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /demo-vulnerable-lib/ })).toHaveCount(0);
  });

  test("vulnerable package -> advisory detail -> every parent path", async () => {
    await page.getByRole("button", { name: "critical", exact: true }).click(); // clear the severity filter
    await page.getByRole("button", { name: /demo-vulnerable-lib/ }).click();
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByText("DEMO-GHSA-0001").first()).toBeVisible();
    await expect(drawer.getByText("DEMO-OSV-0001")).toBeVisible(); // merged alias duplicate, not a second finding
    await expect(drawer.getByText("demo-framework-a@2.0.0", { exact: true })).toBeVisible();
    await expect(drawer.getByText("demo-framework-b@4.0.0", { exact: true })).toBeVisible();
    await expect(drawer.getByText(/Removing one parent does not remove the package/)).toBeVisible();
    await expect(drawer.getByText(/Fixed in/).first()).toContainText("1.2.5");
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
  });

  test("triage requires rationale and expiry, and keeps an audit trail", async () => {
    await page.getByRole("button", { name: /demo-glob/ }).click();
    const drawer = page.getByRole("dialog");
    await drawer.getByLabel("New status").selectOption("accepted_risk");
    await expect(drawer.getByRole("button", { name: "Save triage decision" })).toBeDisabled();
    await drawer.getByLabel(/Rationale/).fill("dev-only dependency, not shipped");
    await drawer.getByLabel(/Expires/).fill("2099-01-01");
    await drawer.getByRole("button", { name: "Save triage decision" }).click();
    await expect(drawer.getByText("Audit trail")).toBeVisible();
    await page.keyboard.press("Escape");
  });

  test("graph highlights both paths to the shared transitive package", async () => {
    await page.getByRole("link", { name: "Dependency Graph" }).first().click();
    await expect(page.getByRole("application", { name: /Dependency graph with \d+ nodes/ })).toBeVisible();
    await page.locator(".react-flow__node", { hasText: "demo-vulnerable-lib" }).click();
    await expect(page.getByText(/Highlighted: 3 package/)).toBeVisible();
    await expect(page.locator(".react-flow__edge.animated")).toHaveCount(4);
  });

  test("candidate lockfile is rescanned; delta and caveats are shown", async () => {
    await page.getByRole("link", { name: "Remediation Studio" }).first().click();
    await page.getByRole("tab", { name: "Candidate lockfile" }).click();
    await page.getByLabel("Choose candidate files").setInputFiles(ex("npm-remediated", "package-lock.json"));
    await page.getByRole("button", { name: "Rescan candidate" }).click();
    await expect(page.getByText("Confirmed by candidate scan").first()).toBeVisible();
    await expect(page.getByText("full re-resolution: yes")).toBeVisible();
    await expect(page.getByText("demo-newdep").first()).toBeVisible(); // newly introduced by the update
    // hypothetical mode must never claim full re-resolution
    await page.getByRole("tab", { name: "What-if" }).click();
    await page.getByLabel("Package").first().selectOption({ label: "demo-parser@0.9.0 · 1 advisory" });
    await page.getByLabel("Target version").fill("0.9.3");
    await page.getByRole("button", { name: "Simulate" }).click();
    await expect(page.getByText("Predicted (partial)").first()).toBeVisible();
    await expect(page.getByText("full re-resolution: no")).toBeVisible();
  });

  test("advisory refresh + new release are compared with correct causes", async () => {
    await importFile(page, ex("npm-vulnerable", "package-lock.json"), "Frozen snapshot · demo-2026-10-20 (2026-10-20)", "release 1.0 refreshed");
    await importFile(page, ex("npm-remediated", "package-lock.json"), "Frozen snapshot · demo-2026-10-20 (2026-10-20)", "release 1.1");
    await page.getByRole("link", { name: "Compare & Timeline" }).first().click();
    await pick(page.getByLabel("Earlier (left)"), /release 1\.0 ·/);
    await pick(page.getByLabel("Later (right)"), /release 1\.0 refreshed/);
    await expect(page.getByText("advisory database update").first()).toBeVisible();
    await expect(page.getByText("The dependency inventory is identical")).toBeVisible();
  });

  test("policy outcome matches CLI semantics", async () => {
    await page.getByRole("link", { name: "Policies & CI" }).first().click();
    const strict = (await import("node:fs")).readFileSync(ex("policy-strict.yaml"), "utf8");
    await page.getByLabel("Policy YAML").fill(strict);
    await page.getByRole("button", { name: "Validate" }).click();
    await expect(page.getByText(/Valid: “strict-new-findings”/)).toBeVisible();
    await page.getByRole("button", { name: "Save policy" }).click();
    await expect(page.getByText("Policy saved.")).toBeVisible();
    await pick(page.getByLabel("Scan to evaluate"), /release 1\.1/);
    await pick(page.getByLabel(/Baseline scan/), /release 1\.0 refreshed/);
    await page.getByRole("button", { name: "Evaluate policy" }).click();
    await expect(page.getByText("CLI exit code")).toContainText("1");
    await expect(page.getByText(/new critical advisory DEMO-GHSA-0004/)).toBeVisible();
  });

  test("report download matches the selected scan", async () => {
    await page.getByRole("link", { name: "Reports & Settings" }).first().click();
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download .sarif" }).click()]);
    const body = (await import("node:fs")).readFileSync((await dl.path())!, "utf8");
    const sarif = JSON.parse(body);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  test("provider outage is shown as an error state, never as a clean scan", async () => {
    await page.getByRole("link", { name: "Projects & Imports" }).first().click();
    await page.getByLabel("Choose dependency files").setInputFiles(ex("npm-clean", "package-lock.json"));
    await page.getByLabel("Advisory source").selectOption({ label: "Live OSV lookup" });
    await expect(page.getByText("Privacy disclosure")).toBeVisible();
    await page.getByLabel("Scan label (optional)").fill("outage");
    await page.getByRole("button", { name: "Import and scan" }).click();
    await expect(page.getByRole("row", { name: /outage/ }).getByText("partial")).toBeVisible({ timeout: 60_000 });
    await page.getByRole("link", { name: "Findings" }).first().click();
    await expect(page.getByText("This list is not exhaustive")).toBeVisible();
    await expect(page.getByText(/not a clean result/)).toBeVisible();
  });

  test("keyboard navigation reaches the main workflows with accessible names", async () => {
    await page.goto("/");
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
    for (const name of ["Overview", "Projects & Imports", "Scan Details", "Dependencies", "Dependency Graph", "Findings", "Remediation Studio", "Compare & Timeline", "Policies & CI", "Reports & Settings"]) {
      await expect(page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name })).toBeVisible();
    }
    await page.getByRole("button", { name: /Switch to light theme/ }).click();
    await expect(page.locator("html")).not.toHaveClass(/dark/);
    await page.getByRole("button", { name: /Switch to dark theme/ }).click();
    await expect(page.locator("html")).toHaveClass(/dark/);
  });
});
