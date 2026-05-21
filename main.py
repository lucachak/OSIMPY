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

import argparse
import asyncio
import sys
from pathlib import Path

from helpers.Crawler import Crawler
from helpers.Executor import Executor


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
        choices=["auto", "google", "duckduckgo", "nodriver"],
        help="Search engine to use (nodriver uses real automated Chrome)",
    )
    parser.add_argument(
        "dorks_option",
        help="Category of dork to use (defined in helpers/manual.py)",
    )
    parser.add_argument(
        "file_type",
        help="Specific file type or sub-category option",
    )
    parser.add_argument(
        "--filter",
        help="Target domain or extension filter (e.g., '.gov.br' or 'target.com')",
    )
    parser.add_argument(
        "--query",
        default="",
        help="Additional search keywords to append to the dork",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run nodriver/Chrome browser in background (invisible) mode",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=30,
        help="Maximum number of search results to retrieve (default: 30)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="./output",
        help="Directory to save JSON results (default: ./output)",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Automatically download discovered files",
    )
    parser.add_argument(
        "--download-dir",
        default="./downloads",
        help="Directory where files will be downloaded (default: ./downloads)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only display execution summary without listing all URLs",
    )

    return parser.parse_args()


async def main():
    args = parse_args()

    # 1. Resolver o caminho absoluto da pasta do perfil
    # Descobre dinamicamente a pasta onde o main.py está e aponta para "chrome_profile"
    BASE_DIR = Path(__file__).parent.resolve()
    PROFILE_DIR = BASE_DIR / "chrome_profile"

    print(f"""
============================================================
 OSYNPY - OSINT Dorking Framework
============================================================
  [*] Engine:        {args.search_engine}
  [*] Category:      {args.dorks_option} -> {args.file_type}
  [*] Filter:        {args.filter or 'None'}
  [*] Extra Query:   {args.query or 'None'}
  [*] Headless Mode: {args.headless}
  [*] Profile Dir:   {PROFILE_DIR}
============================================================
    """)

    # 2. Inicializar o Executor passando o caminho absoluto da pasta pai do perfil
    executor = Executor(
        search_engine=args.search_engine,
        dorks_option=args.dorks_option,
        file_type=args.file_type,
        search_filter=args.filter,
        search_query=args.query,
        headless=args.headless,
        max_results=args.max_results,
        output_dir=args.output,
        user_data_dir=PROFILE_DIR,  # <-- Injetado com sucesso aqui
    )

    # Executar a busca
    print("[*] Building dork and initiating search sequence...")
    result = await executor.execute()

    if result is None:
        print("[!] Execution failed or returned no data.")
        sys.exit(1)

    # Mostrar o resumo da execução no terminal
    print(executor.summary())

    # Listar os links encontrados (a menos que --summary-only tenha sido ativado)
    if not args.summary_only and result.links:
        print(f"\n[+] Links Discovered ({len(result.links)}):")
        for i, link in enumerate(result.links, 1):
            print(f"  {i:3d}. {link}")

    # 3. Lógica de Download síncrono/assíncrono integrada
    should_download = args.download or args.download_dir != "./downloads"
    if should_download and result.links:
        print(f"\n[*] Initializing downloader sequence...")
        # Recria o crawler focado em download reaproveitando a mesma sessão/perfil
        download_crawler = Crawler(
            query=result.dork,
            engine=args.search_engine,
            headless=args.headless,
            download_dir=args.download_dir,
            user_data_dir=PROFILE_DIR,  # <-- Usa a mesma pasta pai
        )
        download_crawler.links = result.links

        # Executa o download em paralelo usando a thread pool do crawler
        downloaded = await asyncio.to_thread(download_crawler.download_all)
        print(
            f"[📥] Successfully downloaded {len(downloaded)} files to '{args.download_dir}'."
        )

    # Mostrar estatísticas globais acumuladas da sessão
    stats = Crawler.stats()
    print(f"""
{'='*60}
SESSION PERFORMANCE STATS
{'='*60}
  Total searches triggered:  {stats.total_searches}
  nodriver success count:    {stats.nodriver_success}
  DuckDuckGo success count:  {stats.duckduckgo_success}
  Google urllib success:     {stats.google_success}
  Total unique links found:  {stats.total_links_found}
{'='*60}
    """)

    # 4. Encerramento seguro do Driver (fecha instâncias do Chrome pendentes)
    print("[*] Post-execution cleanup: Closing shared browser instances...")
    await Crawler.close_driver()
    print("[+] Done.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user (Ctrl+C). Exiting safely.")
        sys.exit(1)

