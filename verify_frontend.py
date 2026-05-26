"""Playwright verification of /runs/new page end-to-end."""
import asyncio
import os

os.environ["LD_LIBRARY_PATH"] = (
    "/home/cks/.cache/ms-playwright/firefox-1522/firefox"
    ":/home/cks/miniforge3/envs/sage/lib"
    + ((":" + os.environ["LD_LIBRARY_PATH"]) if "LD_LIBRARY_PATH" in os.environ else "")
)

from playwright.async_api import async_playwright

ZIP_PATH = "/home/cks/Project/SE-LLM-project/tests/e2e_workspace/cwe_121/target.zip"
FRONTEND = "http://localhost:3000"
SCREENSHOT_DIR = "/tmp/verify_screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={"width": 1400, "height": 900})
        page = await ctx.new_page()

        errors = []
        page.on("console", lambda msg: errors.append(f"[{msg.type}] {msg.text}") if msg.type == "error" else None)
        page.on("pageerror", lambda exc: errors.append(f"[pageerror] {exc}"))

        # ── Step 1: Login page ──────────────────────────────────────────
        print("=== Step 1: Navigate to login page ===")
        await page.goto(f"{FRONTEND}/login")
        await page.wait_for_load_state("networkidle")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/01_login.png")
        print(f"  URL: {page.url}")
        print(f"  Title: {await page.title()}")

        # Find username/password fields (try multiple selectors)
        username_sel = 'input[name="username"], input[type="text"], input[placeholder*="sername"], input[placeholder*="ser"]'
        await page.fill(username_sel, "admin")
        await page.fill('input[type="password"]', "admin123")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/02_login_filled.png")

        # ── Step 2: Submit login ────────────────────────────────────────
        print("\n=== Step 2: Login ===")
        await page.click('button[type="submit"]')
        try:
            await page.wait_for_url(lambda url: "/login" not in url, timeout=10000)
        except Exception:
            # Check for login error
            err_el = page.locator('[class*="error"], [class*="red"], .text-red-400')
            if await err_el.count() > 0:
                print(f"  Login error: {await err_el.first.text_content()}")
            else:
                print("  Still on login page — taking screenshot")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/03_after_login.png")
        print(f"  Redirected to: {page.url}")

        # ── Step 3: Navigate to /runs/new ──────────────────────────────
        print("\n=== Step 3: Navigate to /runs/new ===")
        await page.goto(f"{FRONTEND}/runs/new")
        await page.wait_for_load_state("networkidle")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/04_new_run_form.png")
        print(f"  URL: {page.url}")

        heading = await page.text_content("h1")
        print(f"  Heading: {heading!r}")

        # ── Step 4: Fill form ──────────────────────────────────────────
        print("\n=== Step 4: Fill form ===")
        name_input = page.locator('input[type="text"]').first
        await name_input.fill("cwe_121-stack-overflow-test")
        print("  Filled name: cwe_121-stack-overflow-test")

        file_input = page.locator('input[type="file"]')
        await file_input.set_input_files(ZIP_PATH)
        print(f"  Uploaded: {os.path.basename(ZIP_PATH)}")
        await asyncio.sleep(0.3)
        await page.screenshot(path=f"{SCREENSHOT_DIR}/05_form_filled.png")

        file_name = os.path.basename(ZIP_PATH)
        file_shown = await page.locator(f"text={file_name}").is_visible()
        print(f"  File shown in UI: {file_shown}")

        # ── Step 5: Submit ─────────────────────────────────────────────
        print("\n=== Step 5: Submit form ===")
        submit_btn = page.locator('button[type="submit"]')
        btn_text = await submit_btn.text_content()
        print(f"  Submit button text: {btn_text!r}")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/06_before_submit.png")

        await submit_btn.click()

        # ── Step 6: Observe result ─────────────────────────────────────
        print("\n=== Step 6: Wait for run to be created ===")
        run_id = None
        try:
            await page.wait_for_url(
                lambda url: "/runs/" in url and "/runs/new" not in url,
                timeout=30000,
            )
            run_url = page.url
            run_id = run_url.rstrip("/").split("/")[-1]
            print(f"  Run created! URL: {run_url}")
            print(f"  Run ID: {run_id}")
            await page.wait_for_load_state("networkidle", timeout=10000)
            await page.screenshot(path=f"{SCREENSHOT_DIR}/07_run_detail.png")

            body = await page.inner_text("body")
            status_kws = ["pending", "running", "queued", "created", "failed", "completed", "phase"]
            found = [kw for kw in status_kws if kw.lower() in body.lower()]
            print(f"  Status keywords: {found}")
        except Exception as exc:
            await page.screenshot(path=f"{SCREENSHOT_DIR}/07_error.png")
            err_el = page.locator(".text-red-400, [class*='error']")
            if await err_el.count() > 0:
                print(f"  Page error message: {await err_el.first.text_content()}")
            print(f"  Navigation exception: {exc}")

        # ── Step 7: Probes ─────────────────────────────────────────────
        print("\n=== Step 7: Probes ===")

        if run_id:
            print("  Probe A: run appears in /runs list")
            await page.goto(f"{FRONTEND}/runs")
            await page.wait_for_load_state("networkidle")
            await page.screenshot(path=f"{SCREENSHOT_DIR}/08_runs_list.png")
            in_list = await page.locator("text=cwe_121-stack-overflow-test").is_visible()
            print(f"    Run visible in list: {in_list}")

        print("  Probe B: submit without zip → expect validation error")
        await page.goto(f"{FRONTEND}/runs/new")
        await page.wait_for_load_state("networkidle")
        await page.locator('input[type="text"]').first.fill("no-file-test")
        await page.locator('button[type="submit"]').click()
        await asyncio.sleep(0.5)
        err_el = page.locator(".text-red-400")
        if await err_el.count() > 0:
            print(f"    Error shown: {await err_el.first.text_content()!r}")
        else:
            print("    No validation error shown — PROBLEM")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/09_no_file_error.png")

        print("  Probe C: submit without name → expect validation error")
        await page.goto(f"{FRONTEND}/runs/new")
        await page.wait_for_load_state("networkidle")
        file_input = page.locator('input[type="file"]')
        await file_input.set_input_files(ZIP_PATH)
        await page.locator('button[type="submit"]').click()
        await asyncio.sleep(0.5)
        err_el = page.locator(".text-red-400")
        if await err_el.count() > 0:
            print(f"    Error shown: {await err_el.first.text_content()!r}")
        else:
            # The browser's native required validation may kick in
            name_val = await page.locator('input[type="text"]').first.get_attribute("required")
            if name_val is not None:
                print(f"    No JS error but input has required attr — browser validates")
            else:
                print("    No validation error shown — PROBLEM")
        await page.screenshot(path=f"{SCREENSHOT_DIR}/10_no_name_error.png")

        print(f"\n=== Console errors ({len(errors)}) ===")
        for e in errors[:10]:
            print(f"  {e}")

        print(f"\nScreenshots saved to {SCREENSHOT_DIR}/")
        print("Files:", sorted(os.listdir(SCREENSHOT_DIR)))

        await browser.close()


asyncio.run(main())
