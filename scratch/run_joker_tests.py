import asyncio
from helpers.Executor import Executor
from helpers.Crawler import Crawler

async def run_test(category, file_type, query, search_filter=".edu"):
    print(f"\n==================================================")
    print(f"RUNNING CATEGORY: {category} -> {file_type}")
    print(f"==================================================")
    
    executor = Executor(
        search_engine="auto",
        dorks_option=category,
        file_type=file_type,
        search_filter=search_filter,
        search_query=query,
        headless=True,
        max_results=5,
    )
    result = await executor.execute()
    if not result or not result.links:
        print(f"[!] No links found for {category}")
        return None
        
    print(f"[+] Found {len(result.links)} links. Attempting download of first link...")
    
    # Attempt download of first link
    crawler = Crawler(
        query=result.dork,
        engine="auto",
        headless=True,
    )
    # Filter out links containing google/duckduckgo search paths
    valid_links = [l for l in result.links if not any(x in l for x in ["google.com/search", "google.com/ServiceLogin", "duckduckgo.com"])]
    if not valid_links:
        valid_links = [result.links[0]]
        
    crawler.links = [valid_links[0]]
    downloaded = await asyncio.to_thread(crawler.download_all)
    if downloaded:
        print(f"[✅] Successfully downloaded: {downloaded[0]}")
        return downloaded[0]
    else:
        print(f"[!] Download failed for link: {valid_links[0]}")
        return None

async def main():
    # Define test cases for all 9 categories using .edu domains to fetch educational/public files
    tests = [
        ("findFiles", "pdfs", "science syllabus"),
        ("findPanels", "generic_admin", "login"),
        ("findOpen_directories", "general", "courses"),
        ("findLeaks", "credentials_in_txt", "tutorial"),
        ("findDevices", "ip_cameras", "campus"),
        ("findVulnerabilities", "php_info", "PHP Version"),
        ("intelligenceOsint", "academic_documents", "deep learning"),
        ("advancedTechniques", "powerful_combination", "syllabus"),
        ("infrastructure", "kubernetes", "tutorial"),
    ]
    
    downloaded_files = {}
    for cat, ft, q in tests:
        try:
            file_path = await run_test(cat, ft, q)
            if file_path:
                downloaded_files[cat] = str(file_path)
            # Sleep slightly between tests to prevent rate limits
            await asyncio.sleep(2)
        except Exception as e:
            print(f"[!] Error running test for {cat}: {e}")
            
    # Cleanup browser at the end
    await Crawler.close_driver()
            
    print("\n==================================================")
    print("TESTING SUMMARY")
    print("==================================================")
    for cat, path in downloaded_files.items():
        print(f"  {cat:25s}: {path}")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(main())
