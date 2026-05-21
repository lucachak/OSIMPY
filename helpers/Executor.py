import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from helpers.Crawler import Crawler
from helpers.manual import Manual


@dataclass
class ExecutionResult:
    """Structured result from a single execution."""

    dork: str
    search_engine: str
    file_type: str
    search_filter: str | None
    search_query: str
    links: list[str]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    link_count: int = 0

    def __post_init__(self):
        self.link_count = len(self.links)


class Executor:
    """
    Executor class that:
    1. Receives search parameters
    2. Builds the dork query from Manual
    3. Calls Crawler to search
    4. Normalizes and returns results
    """

    def __init__(
        self,
        search_engine: str,
        dorks_option: str,
        file_type: str,
        search_filter: str | None = None,
        search_query: str = "",
        headless: bool = True,
        max_results: int = 30,
        output_dir: str = "./output",
        user_data_dir: str | Path | None = None,  # <-- 1. ADICIONE AQUI
    ):
        self.search_engine = search_engine
        self.dorks_option = dorks_option
        self.file_type = file_type
        self.search_filter = search_filter
        self.search_query = search_query
        self.headless = headless
        self.max_results = max_results
        self.output_dir = Path(output_dir).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.user_data_dir = user_data_dir  # <-- 2. SALVE A VARIÁVEL
        self.result: ExecutionResult | None = None

    # ================================================================
    # Dork Builder
    # ================================================================

    def set_of_actions(self) -> str | None:
        """
        Build the dork query string based on file_type and search_query.

        Returns:
            Formatted dork string ready for search engines.
        """
        try:
            command_key = self.dorks_option  # "find_files"
            file_key = self.file_type  # "pdfs"

            # Match category key case-insensitively and ignore underscores
            normalized_input = command_key.replace("_", "").lower()
            actual_command_key = command_key
            for k in Manual.dorking_commands.keys():
                if k.replace("_", "").lower() == normalized_input:
                    actual_command_key = k
                    break

            # Get the template
            opt = Manual.dorking_commands.get(actual_command_key, {})
            template_data = opt.get(file_key, {})

            if not template_data:
                print(f"[!] No template found for '{command_key}' -> '{file_key}'")
                print(
                    f"    Available keys in '{actual_command_key}': {list(opt.keys())}"
                )
                return None

            if actual_command_key == "osint_pessoal":
                template = template_data.get("dork", template_data.get("example", ""))
            else:
                template = template_data.get("example", "")

            if not template:
                print(
                    f"[!] No template field found for '{command_key}' -> '{file_key}'"
                )
                return None

            print(f"[*] Template found: {template}")
            return self._apply_template(template)

        except Exception as e:
            print(f"[!] Error building dork: {e}")
            import traceback

            traceback.print_exc()
            return None

    def _apply_template(self, template: str) -> str:
        """Apply search_query and search_filter to the template."""
        query = self.search_query.strip()

        # Handle secret OSINT Pessoal feature
        normalized_option = self.dorks_option.replace("_", "").lower()
        if normalized_option == "osintpessoal":
            target_name = query
            if not target_name:
                target_name = self.search_filter.strip() if self.search_filter else ""
            if not target_name:
                raise ValueError("[!] No target name provided.")

            t = template.replace("nome_pessoa", target_name)
            if self.search_filter and self.search_filter != target_name and "." in self.search_filter:
                if "site:" not in t:
                    t = f"{t} site:*{self.search_filter}"
            return t

        match self.file_type:
            # --- FIND FILES ---
            case "pdfs":
                # Replace quoted content with query
                if query:
                    t = re.sub(
                        r"""(['"])(.*?)\1""",
                        lambda m: f"{m.group(1)}{query}{m.group(1)}",
                        template,
                    )
                else:
                    t = template
                # Apply domain filter
                if self.search_filter:
                    t = t.replace("company.com", "*" + self.search_filter)
                return t

            case "word_documents":
                if query:
                    return re.sub(
                        r"""(['"])(.*?)\1""",
                        lambda m: f"{m.group(1)}{query}{m.group(1)}",
                        template,
                    )
                return template

            case "spreadsheets":
                parts = query.split() if query else ["user", "password"]
                user = parts[0] if len(parts) > 0 else "user"
                pwd = parts[1] if len(parts) > 1 else "password"
                t = re.sub(r'"users"', f'"{user}"', template)
                return re.sub(r'"password"', f'"{pwd}"', t)

            case "databases":
                data = query or "password"
                if "INSERT INTO" in query.upper():
                    data = query.upper().split("INSERT INTO", 1)[1].strip()
                return re.sub(
                    r'"password"',
                    f'"{data}"',
                    template,
                    flags=re.IGNORECASE,
                )

            case "configuration_files":
                if query:
                    t = re.sub(
                        r'"DB_PASSWORD"',
                        f'"{query}"',
                        template,
                    )
                else:
                    t = template
                if self.search_filter:
                    t = re.sub(r"-github", f"-{self.search_filter}", t)
                return t

            case "logs":
                parts = query.split() if query else ["error", "php", "warning"]
                e = parts[0] if len(parts) > 0 else "error"
                tech = parts[1] if len(parts) > 1 else "php"
                w = parts[2] if len(parts) > 2 else "warning"
                t = re.sub(r'"error"', f'"{e}"', template)
                t = re.sub(r'"php"', f'"{tech}"', t)
                return re.sub(r'"warning"', f'"{w}"', t)

            case "backups":
                filename = query if query else "backup"
                return re.sub(
                    r'"backup\.zip"',
                    f'"{filename}.zip"',
                    template,
                )

            case "presentations":
                if query:
                    return re.sub(
                        r"""(['"])(.*?)\1""",
                        lambda m: f"{m.group(1)}{query}{m.group(1)}",
                        template,
                    )
                return template

            case "source_code":
                parts = query.split() if query else ["php", "mysql_connect"]
                ext = parts[0] if len(parts) > 0 else "php"
                func = parts[1] if len(parts) > 1 else "mysql_connect"
                t = re.sub(r"filetype:php", f"filetype:{ext}", template)
                return re.sub(r'"mysql_connect"', f'"{func}"', t)

            case "files_by_name":
                filename = query if query else "wp-config.php"
                return re.sub(
                    r'"wp-config\.php"',
                    f'"{filename}"',
                    template,
                )

            # --- Default: return template with site filter if provided ---
            case _:
                print(
                    f"[!] Unknown file_type: '{self.file_type}', returning raw template"
                )
                t = template
                if self.search_filter:
                    if "site:" in t:
                        t = re.sub(r"site:\S+", f"site:*{self.search_filter}", t)
                    else:
                        t = f"site:*{self.search_filter} {t}"
                return t

    # ================================================================
    # Execution
    # ================================================================

    async def execute(self) -> ExecutionResult | None:
        """
        Build dork → Search → Normalize → Save.

        Returns:
            ExecutionResult with links and metadata.
        """
        # Step 1: Build the dork
        dork = self.set_of_actions()
        if not dork:
            print("[!] Failed to build dork query.")
            return None

        print(f"\n{'='*60}")
        print(f"[*] Dork: {dork}")
        print(f"[*] Engine: {self.search_engine}")
        print(f"{'='*60}")

        # Step 2: Search
        crawler = Crawler(
            query=dork,
            engine=self.search_engine,
            headless=self.headless,
            max_results=self.max_results,
            user_data_dir=self.user_data_dir,   # <-- 3. PASSE PARA O CRAWLER AQUI
        )
        links = await crawler.search()

        # Step 3: Normalize
        normalized = await crawler.Normalized()

        # Step 4: Build result
        self.result = ExecutionResult(
            dork=dork,
            search_engine=self.search_engine,
            file_type=self.file_type,
            search_filter=self.search_filter,
            search_query=self.search_query,
            links=normalized,
        )

        # Step 5: Save
        self.save_result()

        return self.result

    # ================================================================
    # Save
    # ================================================================

    def save_result(self) -> Path:
        """Save execution result as JSON."""
        if self.result is None:
            raise ValueError("No result to save. Run execute() first.")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.file_type}_{timestamp}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(asdict(self.result), f, indent=2, ensure_ascii=False)

        print(f"[💾] Saved: {filepath}")
        return filepath

    # ================================================================
    # Summary
    # ================================================================

    def summary(self) -> str:
        """Return a formatted summary of the execution."""
        if self.result is None:
            return "No execution result."

        return (
            f"{'='*60}\n"
            f"EXECUTION SUMMARY\n"
            f"{'='*60}\n"
            f"  Dork:        {self.result.dork}\n"
            f"  Engine:      {self.result.search_engine}\n"
            f"  File Type:   {self.result.file_type}\n"
            f"  Filter:      {self.result.search_filter or 'N/A'}\n"
            f"  Query:       {self.result.search_query or 'N/A'}\n"
            f"  Links Found: {self.result.link_count}\n"
            f"  Timestamp:   {self.result.timestamp}\n"
            f"{'='*60}"
        )

    def __str__(self) -> str:
        return (
            f"Executor(engine={self.search_engine}, "
            f"dorks_option={self.dorks_option}, "
            f"file_type={self.file_type}, "
            f"filter={self.search_filter}, "
            f"query='{self.search_query}')"
        )

    def __repr__(self) -> str:
        return (
            f"Executor({self.search_engine!r}, {self.dorks_option!r}, "
            f"{self.file_type!r}, {self.search_filter!r}, {self.search_query!r})"
        )

