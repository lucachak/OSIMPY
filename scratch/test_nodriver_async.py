import asyncio
import nodriver as uc

async def main():
    print("[*] Starting browser...")
    try:
        browser = await uc.start(headless=True)
        print("[*] Browser started successfully!")
        
        print("[*] Opening page...")
        page = await browser.get("https://www.google.com")
        print("[*] Page opened successfully!")
        
        print("[*] Page title:", await page.evaluate("document.title"))
        
        print("[*] Stopping browser...")
        await browser.stop()
        print("[*] Browser stopped successfully!")
    except Exception as e:
        print("[!] Error:", e)

if __name__ == "__main__":
    asyncio.run(main())
