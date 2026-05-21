import asyncio
import sys
from pathlib import Path

try:
    import nodriver as uc
    HAS_NODRIVER = True
except ImportError:
    HAS_NODRIVER = False

async def main():
    if not HAS_NODRIVER:
        print("[!] nodriver is not installed in this environment.")
        return

    print("==================================================")
    print("DIAGNOSTIC TEST: Launching Browser in GUI Mode")
    print("==================================================")
    
    browser_args = [
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-infobars",
        "--disable-notifications",
    ]
    
    BASE_DIR = Path(__file__).parent.parent.resolve()
    PROFILE_DIR = BASE_DIR / "chrome_profile"
    
    # Clean up locks to prevent singleton conflict
    lock_file = PROFILE_DIR / "SingletonLock"
    if lock_file.exists() or lock_file.is_symlink():
        try:
            lock_file.unlink()
            print("[*] Lock file SingletonLock removed.")
        except Exception as e:
            print(f"[!] Could not remove lock file: {e}")

    start_kwargs = {
        "headless": False,  # Visible GUI mode
        "browser_args": browser_args,
        "no_sandbox": True,
        "sandbox": False,
        "user_data_dir": str(PROFILE_DIR.resolve())
    }

    try:
        print(f"[*] Attempting to launch browser with profile: {PROFILE_DIR}...")
        browser = await uc.start(**start_kwargs)
        print("[✅] Browser launched successfully!")
        
        print("[*] Opening google.com in a new tab...")
        page = await browser.get("https://www.google.com")
        await page.wait(5)
        
        print("[*] Closing browser...")
        await browser.stop()
        print("[✅] Done!")
        
    except Exception as e:
        print("\n==================================================")
        print("[❌] CRITICAL ERROR DURING BROWSER LAUNCH")
        print("==================================================")
        import traceback
        traceback.print_exc()
        print("==================================================")

if __name__ == "__main__":
    asyncio.run(main())
