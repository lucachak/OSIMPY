class Manual:

    browsers_options = [
        "google",
        "duckduckgo",
        "bing",
        "yandex",
        "brave",
        "startpage",
    ]

    dorks_keywords = {
        # Basic / Universal Operators
        "site": {
            "description": "Restricts search to a specific domain or TLD",
            "syntax": "site:domain.com",
            "example": "site:gov.br filetype:pdf",
            "support": "Google, DuckDuckGo, Bing",
        },
        "filetype": {
            "description": "Searches for specific file types",
            "syntax": "filetype:extension",
            "example": 'filetype:sql "password"',
            "support": "Google, DuckDuckGo (ext:), Bing",
        },
        "ext": {
            "description": "Alternative to filetype (used in DuckDuckGo)",
            "syntax": "ext:extension",
            "example": 'ext:env "DB_PASSWORD"',
            "support": "DuckDuckGo, Yandex",
        },
        "intitle": {
            "description": "Searches for term in the page title",
            "syntax": 'intitle:"term"',
            "example": 'intitle:"index of" /admin',
            "support": "Google, DuckDuckGo, Bing",
        },
        "allintitle": {
            "description": "All words must be in the title",
            "syntax": "allintitle:word1 word2",
            "example": "allintitle:admin login panel",
            "support": "Google",
        },
        "inurl": {
            "description": "Searches for term in the page URL",
            "syntax": "inurl:term",
            "example": "inurl:/phpmyadmin",
            "support": "Google, DuckDuckGo, Bing",
        },
        "allinurl": {
            "description": "All words must be in the URL",
            "syntax": "allinurl:word1 word2",
            "example": "allinurl:admin login.asp",
            "support": "Google",
        },
        "intext": {
            "description": "Searches for term in the page body text",
            "syntax": 'intext:"term"',
            "example": 'intext:"192.168.1." filetype:conf',
            "support": "Google, DuckDuckGo, Bing",
        },
        "allintext": {
            "description": "All words must be in the body text",
            "syntax": "allintext:word1 word2",
            "example": 'allintext:"mysql_fetch_array" "error"',
            "support": "Google",
        },
        "inanchor": {
            "description": "Searches for term in anchor text of links",
            "syntax": 'inanchor:"term"',
            "example": 'inanchor:"click here" site:target.com',
            "support": "Google",
        },
        # Proximity and Context Operators
        "AROUND": {
            "description": "Finds words close to each other (distance n)",
            "syntax": '"word1" AROUND(n) "word2"',
            "example": '"name" AROUND(5) "ssn" filetype:pdf',
            "support": "Google (exclusive)",
        },
        # Time Operators
        "before": {
            "description": "Results before a specific date",
            "syntax": "before:YYYY-MM-DD",
            "example": "site:target.com before:2023-01-01",
            "support": "Google (exclusive)",
        },
        "after": {
            "description": "Results after a specific date",
            "syntax": "after:YYYY-MM-DD",
            "example": '"leak" after:2024-06-01',
            "support": "Google (exclusive)",
        },
        # Cache and History Operators
        "cache": {
            "description": "Shows the cached version of the page stored by Google",
            "syntax": "cache:url.com",
            "example": "cache:target.com/old-page",
            "support": "Google (exclusive)",
        },
        # Logical Operators and Wildcards
        "OR": {
            "description": "Logical OR operator (can use | as alternative)",
            "syntax": "term1 | term2",
            "example": "inurl:(admin | login | dashboard)",
            "support": "Google, DuckDuckGo, Bing",
        },
        "asterisk": {
            "description": "Wildcard that replaces one or more words",
            "syntax": '"word1 * word2"',
            "example": '"user * password *" filetype:txt',
            "support": "Google, DuckDuckGo, Bing",
        },
        "parentheses": {
            "description": "Groups operators for complex logic",
            "syntax": "(term1 | term2) inurl:admin",
            "example": "site:target.com inurl:(admin | login) intitle:(panel | dashboard)",
            "support": "Google, DuckDuckGo, Bing",
        },
        "minus": {
            "description": "Excludes a term from results",
            "syntax": "-term",
            "example": 'intitle:"index of" -github -stackoverflow',
            "support": "Google, DuckDuckGo, Bing",
        },
        "quotes": {
            "description": "Exact phrase search",
            "syntax": '"exact phrase"',
            "example": '"non-disclosure agreement" filetype:pdf',
            "support": "Google, DuckDuckGo, Bing",
        },
        "numeric_range": {
            "description": "Searches for a numeric range",
            "syntax": "number1..number2",
            "example": "camera 100..1000 inurl:8080",
            "support": "Google",
        },
        # DuckDuckGo Specific Operators (Gecko Engine)
        "region": {
            "description": "Restricts results to a specific region",
            "syntax": "region:br",
            "example": 'region:br site:gov.br "bidding"',
            "support": "DuckDuckGo (exclusive)",
        },
        "safeoff": {
            "description": "Disables safe content filter (shows everything)",
            "syntax": "safeoff:",
            "example": "safeoff: inurl:admin",
            "support": "DuckDuckGo (exclusive)",
        },
        # Google Threat Intelligence Operators
        "domain": {
            "description": "Searches for domains in Google Threat Intelligence",
            "syntax": "domain: /regex/",
            "example": "domain: /google.*\\.xyz/ malicious_detections:>5",
            "support": "Google Threat Intelligence (exclusive)",
        },
        "malicious_detections": {
            "description": "Filters by malicious detections in GTI",
            "syntax": "malicious_detections:>N",
            "example": "malicious_detections:>3 http_response_code:200",
            "support": "Google Threat Intelligence (exclusive)",
        },
        "http_response_code": {
            "description": "Filters by HTTP response code in GTI",
            "syntax": "http_response_code:CODE",
            "example": "http_response_code:200 domain: /.*\\.tk/",
            "support": "Google Threat Intelligence (exclusive)",
        },
        # Engine-Specific Operators
        "engines": {
            "V8_Google": [
                "site",
                "filetype",
                "intitle",
                "allintitle",
                "inurl",
                "allinurl",
                "intext",
                "allintext",
                "inanchor",
                "AROUND",
                "before",
                "after",
                "cache",
                "numeric_range",
                "OR",
                "asterisk",
                "parentheses",
                "minus",
                "quotes",
            ],
            "Gecko_DuckDuckGo": [
                "site",
                "ext",
                "intitle",
                "inurl",
                "intext",
                "region",
                "safeoff",
                "OR",
                "asterisk",
                "parentheses",
                "minus",
                "quotes",
            ],
            "Bing": [
                "site",
                "filetype",
                "intitle",
                "inurl",
                "intext",
                "OR",
                "asterisk",
                "parentheses",
                "minus",
                "quotes",
            ],
            "Google_Threat_Intelligence": [
                "domain",
                "malicious_detections",
                "http_response_code",
            ],
        },
    }

    dorking_commands = {
        # ============================================================
        # 1. FIND SPECIFIC FILES
        # ============================================================
        "findFiles": {
            "pdfs": {
                "description": "Locate PDF documents",
                "dork": 'filetype:pdf "keyword"',
                "example": 'filetype:pdf "financial report" site:company.com',
            },
            "spreadsheets": {
                "description": "Locate Excel, CSV and similar",
                "dork": "filetype:xlsx | filetype:csv | filetype:xls",
                "example": 'filetype:xlsx "users" "password"',
            },
            "word_documents": {
                "description": "Locate Word documents",
                "dork": "filetype:docx | filetype:doc",
                "example": 'filetype:docx "confidential contract"',
            },
            "databases": {
                "description": "Locate SQL dumps and databases",
                "dork": "filetype:sql | filetype:db | filetype:mdb",
                "example": 'filetype:sql "INSERT INTO" "password"',
            },
            "configuration_files": {
                "description": "Locate .env, .cfg, .conf, .ini, .yaml",
                "dork": "filetype:env | filetype:cfg | filetype:conf | filetype:yaml",
                "example": 'filetype:env "DB_PASSWORD" -github',
            },
            "logs": {
                "description": "Locate exposed log files",
                "dork": "filetype:log | filetype:txt inurl:log",
                "example": 'filetype:log "error" "php" "warning"',
            },
            "backups": {
                "description": "Locate backup files (.bak, .zip, .tar, .gz)",
                "dork": 'filetype:bak | filetype:zip | filetype:tar | filetype:gz "backup"',
                "example": 'intitle:"index of" "backup.zip"',
            },
            "presentations": {
                "description": "Locate PowerPoint and similar",
                "dork": "filetype:pptx | filetype:ppt",
                "example": 'filetype:pptx "strategic planning"',
            },
            "source_code": {
                "description": "Locate exposed scripts and source code",
                "dork": "filetype:php | filetype:py | filetype:js | filetype:java",
                "example": 'filetype:php intext:"mysql_connect"',
            },
            "files_by_name": {
                "description": "Locate a file by exact name",
                "dork": 'intitle:"index of" "filename.ext"',
                "example": 'intitle:"index of" "wp-config.php"',
            },
        },
        # ============================================================
        # 2. FIND LOGIN PANELS / ADMIN PAGES
        # ============================================================
        "findPanels": {
            "generic_admin": {
                "description": "Generic administration panels",
                "dork": "inurl:admin intitle:login",
                "example": "site:target.com inurl:admin intitle:login",
            },
            "phpmyadmin": {
                "description": "Exposed phpMyAdmin panels",
                "dork": 'intitle:"phpMyAdmin" inurl:"/phpmyadmin"',
                "example": 'intitle:"phpMyAdmin" "Welcome to"',
            },
            "wordpress": {
                "description": "WordPress panels",
                "dork": "inurl:/wp-admin | inurl:/wp-login.php",
                "example": "site:target.com inurl:/wp-admin",
            },
            "cpanel": {
                "description": "cPanel/WHM panels",
                "dork": 'inurl:"/cpanel" | intitle:"cPanel"',
                "example": "inurl:2083 intitle:login",
            },
            "joomla": {
                "description": "Joomla panels",
                "dork": 'inurl:/administrator intitle:"Joomla"',
                "example": "site:target.com inurl:/administrator",
            },
            "drupal": {
                "description": "Drupal panels",
                "dork": 'inurl:/user/login intitle:"Log in"',
                "example": "site:target.com inurl:/user/login",
            },
            "mikrotik": {
                "description": "Exposed MikroTik routers",
                "dork": 'intitle:"MikroTik RouterOS" inurl:webfig',
                "example": 'intitle:"RouterOS" "configuration"',
            },
            "webmin": {
                "description": "Webmin panels",
                "dork": 'intitle:"Webmin" inurl:10000',
                "example": 'intitle:"Login to Webmin"',
            },
            "jenkins": {
                "description": "Jenkins CI/CD servers",
                "dork": 'intitle:"Dashboard [Jenkins]"',
                "example": 'inurl:8080 intitle:"Jenkins"',
            },
            "gitlab": {
                "description": "GitLab instances",
                "dork": 'intitle:"Sign in · GitLab"',
                "example": 'inurl:/users/sign_in intitle:"GitLab"',
            },
        },
        # ============================================================
        # 3. FIND OPEN DIRECTORIES
        # ============================================================
        "findOpen_directories": {
            "general": {
                "description": "Any directory with listing enabled",
                "dork": 'intitle:"index of"',
                "example": 'intitle:"index of" /admin',
            },
            "ftp": {
                "description": "Exposed FTP directories",
                "dork": 'intitle:"index of" inurl:ftp',
                "example": 'intitle:"index of" inurl:ftp "pub"',
            },
            "backup": {
                "description": "Directories with backup files",
                "dork": 'intitle:"index of" "backup"',
                "example": 'intitle:"index of" "backup.sql"',
            },
            "uploads": {
                "description": "Exposed upload directories",
                "dork": 'intitle:"index of" inurl:uploads',
                "example": 'site:target.com intitle:"index of" inurl:uploads',
            },
            "wp_content": {
                "description": "Exposed WordPress wp-content directory",
                "dork": 'intitle:"index of" inurl:wp-content',
                "example": 'site:target.com intitle:"index of" /wp-content/uploads',
            },
            "exposed_git": {
                "description": "Exposed .git repositories",
                "dork": 'intitle:"index of" ".git"',
                "example": 'intitle:"index of" ".git/config"',
            },
            "credential_folders": {
                "description": "Directories with password/config files",
                "dork": 'intitle:"index of" "password" | "config" | "secret"',
                "example": 'intitle:"index of" "credentials.txt"',
            },
        },
        # ============================================================
        # 4. FIND SENSITIVE INFORMATION / LEAKS
        # ============================================================
        "findLeaks": {
            "credentials_in_txt": {
                "description": "Text files with credentials",
                "dork": 'filetype:txt "password" | "pass" | "login"',
                "example": 'filetype:txt intext:"password=" intext:"username="',
            },
            "api_keys": {
                "description": "Leaked API keys",
                "dork": 'filetype:env "API_KEY" | "TOKEN" | "SECRET" -github',
                "example": 'filetype:env "AWS_SECRET_ACCESS_KEY"',
            },
            "emails": {
                "description": "Exposed email lists",
                "dork": 'filetype:xlsx "@gmail.com" | "@hotmail.com"',
                "example": 'site:target.com filetype:csv "@"',
            },
            "ssn_id": {
                "description": "Documents with SSN/ID numbers",
                "dork": 'filetype:pdf "SSN" | "ID" "No."',
                "example": 'site:gov filetype:pdf "SSN" -template -example',
            },
            "credit_card": {
                "description": "Possible credit card leaks",
                "dork": 'filetype:txt "4111" | "5502" | "3400"',
                "example": 'filetype:log intext:"cvv" "expiration"',
            },
            "sql_credentials": {
                "description": "SQL dumps with user tables",
                "dork": 'filetype:sql "INSERT INTO" "users" "password"',
                "example": 'filetype:sql intext:"admin" intext:"hash"',
            },
            "internal_documents": {
                "description": "Documents marked as confidential",
                "dork": 'filetype:pdf "confidential" | "internal" | "restricted"',
                "example": 'site:company.com filetype:pdf "confidential"',
            },
            "pastebin_leaks": {
                "description": "Leaks posted on PasteBin",
                "dork": 'site:pastebin.com "company" "password"',
                "example": 'site:pastebin.com "company_name" "leak"',
            },
        },
        # ============================================================
        # 5. FIND DEVICES / IOT
        # ============================================================
        "findDevices": {
            "ip_cameras": {
                "description": "Exposed IP cameras",
                "dork": 'inurl:"view/viewer_index.shtml" | intitle:"webcam" inurl:8080',
                "example": 'intitle:"Live View" inurl:"/view/"',
            },
            "dvr_nvr": {
                "description": "Video recorders (DVR/NVR)",
                "dork": 'intitle:"DVR" inurl:login | intitle:"NVR"',
                "example": 'intitle:"DVR Login" -github',
            },
            "printers": {
                "description": "Exposed network printers",
                "dork": 'intitle:"HP" inurl:9100 | inurl:631 "printer"',
                "example": 'intitle:"LaserJet" inurl:"/hp/device"',
            },
            "routers": {
                "description": "Routers with web interface",
                "dork": 'intitle:"TP-Link" | intitle:"NETGEAR" | intitle:"D-Link"',
                "example": 'intitle:"TP-Link" inurl:admin',
            },
            "nas_storage": {
                "description": "NAS devices (Synology, QNAP)",
                "dork": 'intitle:"Synology" | intitle:"QNAP"',
                "example": 'intitle:"Synology DiskStation" inurl:5000',
            },
            "scada_ics": {
                "description": "Industrial SCADA/ICS systems",
                "dork": 'intitle:"PLC" | intitle:"SCADA" | intitle:"HMI"',
                "example": 'inurl:/Portal0000.htm intitle:"HMI"',
            },
        },
        # ============================================================
        # 6. FIND SPECIFIC VULNERABILITIES
        # ============================================================
        "findVulnerabilities": {
            "sql_injection": {
                "description": "Potentially injectable parameters",
                "dork": 'inurl:".php?id=" | inurl:".aspx?page=" | inurl:"?prod="',
                "example": 'site:target.com inurl:"?id=" inurl:".php"',
            },
            "xss": {
                "description": "Possible reflected XSS points",
                "dork": 'inurl:"?search=" | inurl:"&q=" | inurl:"?query="',
                "example": 'site:target.com inurl:"?search="',
            },
            "sql_error": {
                "description": "Exposed SQL error messages",
                "dork": 'intext:"you have an error in your sql syntax"',
                "example": 'intext:"mysql_fetch_array" intext:"warning"',
            },
            "php_info": {
                "description": "Exposed phpinfo() pages",
                "dork": 'intitle:"phpinfo()" "PHP Version"',
                "example": 'ext:php intitle:"phpinfo"',
            },
            "debug_mode": {
                "description": "Debug mode enabled in production",
                "dork": 'intext:"debug" intext:"true" filetype:env',
                "example": 'intext:"APP_DEBUG=true" filetype:env',
            },
            "software_version": {
                "description": "Specific software versions (fingerprinting)",
                "dork": 'intitle:"Apache2 Ubuntu Default Page"',
                "example": 'intitle:"Apache Status" "Server Version"',
            },
            "open_redirect": {
                "description": "Possible redirect parameters",
                "dork": 'inurl:"?redirect=" | inurl:"?url=" | inurl:"?return="',
                "example": 'site:target.com inurl:"?redirect=http"',
            },
            "local_file_inclusion": {
                "description": "Possible LFI points",
                "dork": 'inurl:"?file=" | inurl:"?page=" | inurl:"?path="',
                "example": 'site:target.com inurl:"?page=" ext:php',
            },
        },
        # ============================================================
        # 7. INTELLIGENCE / OSINT / RECONNAISSANCE
        # ============================================================
        "intelligenceOsint": {
            "subdomains": {
                "description": "Discover subdomains of a target",
                "dork": "site:*.domain.com -www",
                "example": "site:*.gov -www -mail",
            },
            "linkedin_employees": {
                "description": "Find employee profiles",
                "dork": 'site:linkedin.com/in "company" "position"',
                "example": 'site:linkedin.com/in "Google" "software engineer"',
            },
            "government_documents": {
                "description": "Documents on .gov sites",
                "dork": 'site:gov filetype:pdf "contract"',
                "example": 'site:gov filetype:pdf "contract" "value"',
            },
            "academic_documents": {
                "description": "Theses and research on .edu sites",
                "dork": 'site:edu filetype:pdf "thesis" | "dissertation"',
                "example": 'site:edu filetype:pdf "artificial intelligence"',
            },
            "target_technologies": {
                "description": "Identify technologies used",
                "dork": 'site:target.com "powered by" | "built with"',
                "example": 'site:target.com intext:"wp-content"',
            },
            "robots_txt": {
                "description": "Read robots.txt from a site via cache",
                "dork": "cache:target.com/robots.txt",
                "example": "cache:company.com/robots.txt",
            },
            "sitemap": {
                "description": "Find indexed sitemaps",
                "dork": "site:target.com filetype:xml inurl:sitemap",
                "example": "site:company.com inurl:sitemap.xml",
            },
            "web_archive": {
                "description": "View old versions of pages (need to access archive.org afterwards)",
                "dork": "cache:target.com/old-page",
                "example": "cache:company.com/team (removed employee page)",
            },
        },
        # ============================================================
        # 8. ADVANCED OPERATOR SEARCHES
        # ============================================================
        "advancedTechniques": {
            "word_proximity": {
                "description": "Find words close together (context)",
                "dork": '"word1" AROUND(N) "word2"',
                "example": '"password" AROUND(5) "admin" filetype:txt',
            },
            "specific_date": {
                "description": "Results before/after a date",
                "dork": "before:YYYY-MM-DD | after:YYYY-MM-DD",
                "example": 'site:target.com "leak" after:2024-01-01',
            },
            "numeric_range": {
                "description": "Search by number range (IPs, ports)",
                "dork": "number1..number2",
                "example": 'intext:"192.168.1." 1..254',
            },
            "multiple_exclusion": {
                "description": "Remove false positives from search",
                "dork": "-term1 -term2 -term3",
                "example": 'intitle:"index of" -github -stackoverflow -gitlab',
            },
            "logical_grouping": {
                "description": "Combine multiple operators with logic",
                "dork": "site:target.com inurl:(admin | login | dashboard) intitle:(login | panel | access)",
                "example": 'site:gov filetype:(pdf | xlsx | docx) "contract"',
            },
            "powerful_combination": {
                "description": "Multi-operator dork for precise search",
                "dork": 'site:target.com filetype:pdf intitle:"report" intext:"confidential" after:2023-01-01 -template -example',
                "example": 'site:company.com filetype:env "DB_PASSWORD" -github -gitlab -bitbucket',
            },
        },
        # ============================================================
        # 9. FIND INFRASTRUCTURE RESOURCES
        # ============================================================
        "infrastructure": {
            "s3_buckets_aws": {
                "description": "Exposed Amazon S3 buckets",
                "dork": 'site:s3.amazonaws.com "Company Name"',
                "example": 'site:s3.amazonaws.com "backup" "db"',
            },
            "kubernetes": {
                "description": "Kubernetes configuration files",
                "dork": 'filetype:yaml "kind: Config" | "kubeconfig"',
                "example": 'filetype:yaml "apiVersion: v1" "token"',
            },
            "docker": {
                "description": "Dockerfile and docker-compose files",
                "dork": 'filetype:yml "docker-compose" | filetype:yaml "services:"',
                "example": 'filetype:yml intext:"image:" intext:"ports:"',
            },
            "terraform": {
                "description": "Terraform files with state",
                "dork": 'filetype:tf "terraform" | filetype:tfstate',
                "example": 'filetype:tfstate "aws_access_key"',
            },
            "jenkinsfile": {
                "description": "Exposed Jenkins pipelines",
                "dork": 'filetype:jenkinsfile | intitle:"Jenkinsfile"',
                "example": 'filetype:groovy intext:"pipeline" intext:"agent"',
            },
            "ssh_keys": {
                "description": "Exposed private SSH keys",
                "dork": 'filetype:pem "PRIVATE KEY" | filetype:ppk',
                "example": 'intitle:"index of" "id_rsa" -github',
            },
        },
        # ============================================================
        # 10. EXPERIMENTAL!
        # ============================================================
        "osint_pessoal": {
            "documentos_pessoais": {
                "description": "Localiza documentos que mencionam o nome da pessoa (PDFs, planilhas, docs)",
                "dork": 'filetype:pdf | filetype:xlsx | filetype:docx | filetype:csv "nome_pessoa"',
                "example": 'filetype:pdf "fulano de tal"',
            },
            "curriculos": {
                "description": "Encontra currículos e portfólios da pessoa",
                "dork": 'filetype:pdf "nome_pessoa" (curriculum OR curriculo OR cv OR resume OR portfolio)',
                "example": 'filetype:pdf "fulano de tal" (curriculum OR cv OR resume)',
            },
            "redes_sociais": {
                "description": "Localiza perfis em redes sociais",
                "dork": '(site:linkedin.com/in | site:instagram.com | site:twitter.com | site:facebook.com | site:tiktok.com | site:github.com | site:gitlab.com | site:medium.com | site:dev.to | site:stackoverflow.com/users | site:behance.net | site:dribbble.com | site:youtube.com/@ | site:reddit.com/user) "nome_pessoa"',
                "example": '(site:linkedin.com/in | site:github.com) "fulano de tal"',
            },
            "foruns_comunidades": {
                "description": "Encontra posts e menções em fóruns e comunidades",
                "dork": '(site:reddit.com | site:quora.com | site:stackexchange.com | site:superuser.com | site:serverfault.com | site:mathoverflow.net | site:askubuntu.com | site:pt.stackoverflow.com) "nome_pessoa"',
                "example": 'site:reddit.com "fulano de tal"',
            },
            "sites_governamentais": {
                "description": "Localiza menções em sites governamentais, processos e diários oficiais",
                "dork": '(site:gov.br | site:jusbrasil.com.br | site:diariomunicipal.com.br | site:transparencia.gov.br | site:cnpj.biz | site:consultasocio.com) "nome_pessoa"',
                "example": 'site:gov.br "fulano de tal"',
            },
            "emails_vazados": {
                "description": "Encontra emails associados ao nome",
                "dork": '"nome_pessoa" ("@gmail.com" | "@hotmail.com" | "@outlook.com" | "@yahoo.com" | "@protonmail.com" | "@uol.com.br" | "@bol.com.br" | "@terra.com.br")',
                "example": '"fulano de tal" ("@gmail.com" | "@hotmail.com")',
            },
            "telefone_contato": {
                "description": "Busca por números de telefone associados ao nome",
                "dork": '"nome_pessoa" ("tel:" | "telefone:" | "whatsapp:" | "contato:" | "(11)" | "(21)" | "(31)" | "(41)" | "(51)" | "(61)" | "(71)" | "(81)" | "(91)")',
                "example": '"fulano de tal" ("tel:" | "whatsapp:" | "(11)")',
            },
            "cpf_rg_documentos": {
                "description": "Encontra CPF, RG e outros documentos de identificação",
                "dork": 'filetype:pdf | filetype:xlsx | filetype:csv | filetype:txt "nome_pessoa" ("CPF" | "RG" | "identidade" | "passaporte" | "CNH" | "título de eleitor" | "pis" | "pasep" | "carteira de trabalho")',
                "example": 'filetype:pdf "fulano de tal" ("CPF" | "RG")',
            },
            "endereco_residencial": {
                "description": "Busca por endereços associados ao nome",
                "dork": '"nome_pessoa" ("rua" | "avenida" | "alameda" | "praça" | "travessa" | "rodovia" | "estrada" | "bairro" | "cidade" | "estado" | "cep")',
                "example": '"fulano de tal" ("rua" | "avenida" | "cep")',
            },
            "fotos_imagens": {
                "description": "Encontra fotos e imagens indexadas com o nome",
                "dork": 'intitle:"nome_pessoa" (filetype:jpg | filetype:jpeg | filetype:png | filetype:gif | filetype:webp)',
                "example": 'intitle:"fulano de tal" filetype:jpg',
            },
            "pastas_abertas": {
                "description": "Localiza diretórios abertos com arquivos da pessoa",
                "dork": 'intitle:"index of" "nome_pessoa"',
                "example": 'intitle:"index of" "fulano de tal"',
            },
            "registros_dominios": {
                "description": "Encontra domínios registrados pela pessoa (WHOIS reverso)",
                "dork": '"nome_pessoa" (site:registro.br | site:whois.com | site:who.is)',
                "example": '"fulano de tal" site:registro.br',
            },
            "publicacoes_academicas": {
                "description": "Localiza artigos, teses e publicações acadêmicas",
                "dork": '"nome_pessoa" (site:researchgate.net | site:scholar.google.com | site:academia.edu | site:lattes.cnpq.br | site:orcid.org | site:scopus.com)',
                "example": '"fulano de tal" site:lattes.cnpq.br',
            },
            "pastebin_vazamentos": {
                "description": "Encontra vazamentos e dumps postados em sites de texto",
                "dork": '(site:pastebin.com | site:justpaste.it | site:controlc.com | site:rentry.co | site:telegra.ph | site:ghostbin.co | site:0bin.net) "nome_pessoa"',
                "example": 'site:pastebin.com "fulano de tal"',
            },
            "credenciais_senhas": {
                "description": "Busca por credenciais e senhas associadas ao nome",
                "dork": 'filetype:txt | filetype:env | filetype:log | filetype:cfg | filetype:conf "nome_pessoa" ("password" | "senha" | "login" | "username" | "user" | "email" | "token" | "api_key" | "secret")',
                "example": 'filetype:txt "fulano de tal" ("password" | "senha")',
            },
            "bancos_dados_expostos": {
                "description": "Procura por dumps de banco de dados contendo o nome",
                "dork": 'filetype:sql | filetype:db | filetype:mdb | filetype:sqlite "nome_pessoa"',
                "example": 'filetype:sql "fulano de tal"',
            },
            "backups_zipados": {
                "description": "Encontra backups que contenham informações da pessoa",
                "dork": 'filetype:zip | filetype:tar | filetype:gz | filetype:rar | filetype:7z | filetype:bak "nome_pessoa"',
                "example": 'filetype:zip "fulano de tal"',
            },
            "mensagens_chats": {
                "description": "Localiza logs de chat e mensagens mencionando a pessoa",
                "dork": '(filetype:log | filetype:txt) "nome_pessoa" ("chat" | "whatsapp" | "telegram" | "discord" | "skype" | "messenger" | "signal")',
                "example": 'filetype:log "fulano de tal" ("whatsapp" | "telegram")',
            },
            "compras_online": {
                "description": "Encontra perfis de compras e marketplaces",
                "dork": '"nome_pessoa" (site:mercadolivre.com.br | site:olx.com.br | site:ebay.com | site:amazon.com | site:shopee.com.br | site:aliexpress.com | site:enjoei.com.br | site:elo7.com.br)',
                "example": '"fulano de tal" site:mercadolivre.com.br',
            },
            "registros_imobiliarios": {
                "description": "Busca por registros de imóveis e propriedades",
                "dork": '"nome_pessoa" ("iptu" | "escritura" | "matrícula" | "registro de imóveis" | "cartório" | "proprietário" | "inquilino" | "locatário")',
                "example": '"fulano de tal" ("iptu" | "escritura")',
            },
            "processos_juridicos": {
                "description": "Encontra processos judiciais e ações legais",
                "dork": '"nome_pessoa" ("processo" | "ação" | "reclamatória" | "execução" | "mandado" | "intimação" | "citação" | "sentença" | "acórdão" | "tribunal" | "vara" | "juizado")',
                "example": '"fulano de tal" ("processo" | "tribunal")',
            },
            "veiculos_transporte": {
                "description": "Busca por veículos e transportes associados ao nome",
                "dork": '"nome_pessoa" ("placa" | "renavam" | "chassi" | "detran" | "ipva" | "licenciamento" | "multa" | "infração")',
                "example": '"fulano de tal" ("placa" | "detran")',
            },
            "registros_empresariais": {
                "description": "Localiza participação em empresas e sociedades",
                "dork": '"nome_pessoa" ("sócio" | "administrador" | "proprietário" | "fundador" | "presidente" | "diretor" | "cnpj" | "razão social" | "nome fantasia" | "mei" | "eireli" | "ltda")',
                "example": '"fulano de tal" ("sócio" | "cnpj")',
            },
            "certidoes_documentos_oficiais": {
                "description": "Encontra certidões e documentos oficiais",
                "dork": '"nome_pessoa" ("certidão" | "nascimento" | "casamento" | "óbito" | "naturalidade" | "filiação" | "nacionalidade" | "estado civil")',
                "example": '"fulano de tal" ("certidão" | "nascimento")',
            },
            "registros_eleitorais": {
                "description": "Busca por informações eleitorais e filiação partidária",
                "dork": '"nome_pessoa" ("título de eleitor" | "zona eleitoral" | "seção" | "filiação partidária" | "candidato" | "eleito" | "votação")',
                "example": '"fulano de tal" ("título de eleitor" | "candidato")',
            },
            "saude_registros_medicos": {
                "description": "Procura por registros médicos e de saúde (CUIDADO: dados sensíveis)",
                "dork": 'filetype:pdf | filetype:xlsx "nome_pessoa" ("prontuário" | "receita" | "exame" | "diagnóstico" | "crm" | "hospital" | "clínica" | "plano de saúde" | "unimed" | "bradesco saúde" | "sulamerica")',
                "example": 'filetype:pdf "fulano de tal" ("exame" | "hospital")',
            },
            "educacao_historico": {
                "description": "Encontra histórico educacional e diplomas",
                "dork": '"nome_pessoa" ("diploma" | "histórico escolar" | "certificado" | "graduação" | "mestrado" | "doutorado" | "ensino médio" | "ensino fundamental" | "enem" | "vestibular" | "universidade" | "faculdade")',
                "example": '"fulano de tal" ("diploma" | "universidade")',
            },
            "assinaturas_servicos": {
                "description": "Localiza assinaturas e serviços contratados",
                "dork": '"nome_pessoa" ("assinatura" | "contrato" | "fatura" | "boleto" | "netflix" | "spotify" | "amazon prime" | "disney plus" | "claro" | "vivo" | "tim" | "oi")',
                "example": '"fulano de tal" ("assinatura" | "fatura")',
            },
            "deep_web_index": {
                "description": "Busca por menções em sites de indexação profunda",
                "dork": '"nome_pessoa" (site:archive.org | site:web.archive.org | site:cachedview.com | site:search.casa)',
                "example": '"fulano de tal" site:archive.org',
            },
            "combinacao_maxima": {
                "description": "Dork combinada para máximo de informações possíveis",
                "dork": 'filetype:pdf | filetype:xlsx | filetype:docx | filetype:csv | filetype:txt | filetype:sql | filetype:env | filetype:log "nome_pessoa" ("cpf" | "rg" | "endereço" | "telefone" | "email" | "senha" | "password" | "cartão" | "banco" | "conta" | "agência")',
                "example": 'filetype:pdf | filetype:xlsx | filetype:docx | filetype:csv | filetype:txt | filetype:sql | filetype:env | filetype:log "nome_pessoa" ("cpf" | "rg" | "endereço" | "telefone" | "email" | "senha" | "password" | "cartão" | "banco" | "conta" | "agência")',
            },
        },
    }

