import asyncio
import nodriver as uc

async def main():
    browser = await uc.start(headless=True)
    page = await browser.get("https://www.google.com/search?q=test")
    await page.wait(3.0)
    html = await page.get_content()
    with open("google_dump.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("Google search page dumped to google_dump.html")
    await browser.aclose()

if __name__ == "__main__":
    asyncio.run(main())
