#!/usr/bin/env python3
"""
Google Dork Automation Tool

Usage:
    python main.py <search_engine> <dorks_option> <file_type> [--filter <domain>] [--query <text>] [--headless] [--max-results <n>]

Examples:
    python main.py auto find_files pdfs --filter .com.br --query "financial report"
    python main.py duckduckgo find_files databases --query "users"
    python main.py nodriver find_leaks api_keys --filter github.com
    python main.py auto find_files spreadsheets --query "admin password123"
    python main.py auto find_files files_by_name --query "wp-config.php"
    python main.py auto find_panels phpmyadmin --filter target.com
"""

import sys
import argparse
import asyncio
from helpers.Executor import Executor
from helpers.Crawler import Crawler


def parse_args():
    parser = argparse.ArgumentParser(
        description="Google Dork Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s auto find_files pdfs --filter .com.br --query "financial report"
  %(prog)s duckduckgo find_files databases --query "users"
  %(prog)s nodriver find_leaks api_keys --filter github.com
  %(prog)s auto find_files spreadsheets --query "admin password123"
        """,
    )

    parser.add_argument(
        "search_engine",
        choices=["auto", "google", "duckduckgo", "nodriver", "yahoo"],
        help="Search engine to use",
    )
    parser.add_argument(
        "dorks_option",
        help="Dork category (e.g., find_files, find_panels, find_leaks)",
    )
    parser.add_argument(
        "file_type",
        help="File type / sub-category (e.g., pdfs, word_documents, databases)",
    )
    parser.add_argument(
        "--filter", "-f",
        dest="search_filter",
        default=None,
        help="Domain filter (e.g., .com.br, empresa.com)",
    )
    parser.add_argument(
        "--query", "-q",
        dest="search_query",
        default="",
        help="Search query text to inject",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=False,
        help="Run browser in headless mode",
    )
    parser.add_argument(
        "--max-results", "-n",
        type=int,
        default=30,
        help="Maximum results to return (default: 30)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./output",
        help="Output directory for results (default: ./output)",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        default=False,
        help="Download found files",
    )
    parser.add_argument(
        "--download-dir", "-d",
        dest="download_dir",
        default="./downloads",
        help="Directory to save downloaded files (default: ./downloads)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        default=False,
        help="Only print summary, don't show all links",
    )

    return parser.parse_args()


async def main():
    args = parse_args()

    print(f"""
╔══════════════════════════════════════════════════════╗
║           GOOGLE DORK AUTOMATION TOOL               ║
╚══════════════════════════════════════════════════════╝
    Engine:      {args.search_engine}
    Category:    {args.dorks_option}
    File Type:   {args.file_type}
    Filter:      {args.search_filter or 'N/A'}
    Query:       {args.search_query or 'N/A'}
    Headless:    {args.headless}
    Max Results: {args.max_results}
    Output Dir:  {args.output}
    """)

    # Create executor
    executor = Executor(
        search_engine=args.search_engine,
        dorks_option=args.dorks_option,
        file_type=args.file_type,
        search_filter=args.search_filter,
        search_query=args.search_query,
        headless=args.headless,
        max_results=args.max_results,
        output_dir=args.output,
    )

    # Execute
    result = await executor.execute()

    if result is None:
        print("[!] Execution failed.")
        sys.exit(1)

    # Print summary
    print(executor.summary())

    # Print links (unless summary-only)
    if not args.summary_only and result.links:
        print(f"\n[+] Links ({len(result.links)}):")
        for i, link in enumerate(result.links, 1):
            print(f"  {i:3d}. {link}")

    # Download if requested or if a custom download directory is provided
    should_download = args.download or args.download_dir != "./downloads"
    if should_download and result.links:
        # Re-create crawler for download
        crawler = Crawler(
            query=result.dork,
            engine=args.search_engine,
            headless=args.headless,
            download_dir=args.download_dir,
            user_data_dir="./nodriver_profile", 
        )
        crawler.links = result.links
        downloaded = await asyncio.to_thread(crawler.download_all)
        print(f"\n[📥] Downloaded {len(downloaded)} files to '{args.download_dir}'.")

    # Show stats
    stats = Crawler.stats()
    print(f"""
{'='*60}
SESSION STATS
{'='*60}
  Total searches:     {stats.total_searches}
  nodriver success:   {stats.nodriver_success}
  DuckDuckGo success: {stats.duckduckgo_success}
  Google success:     {stats.google_success}
  Total links:        {stats.total_links_found}
  Total time:         {stats.total_time:.1f}s
{'='*60}
    """)

    # Cleanup
    await Crawler.close_driver()


if __name__ == "__main__":
    asyncio.run(main())