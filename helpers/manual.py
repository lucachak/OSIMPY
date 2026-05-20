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
            "example": 'filetype:pdf "financial report" site:company.com'
        },
        "spreadsheets": {
            "description": "Locate Excel, CSV and similar",
            "dork": "filetype:xlsx | filetype:csv | filetype:xls",
            "example": 'filetype:xlsx "users" "password"'
        },
        "word_documents": {
            "description": "Locate Word documents",
            "dork": "filetype:docx | filetype:doc",
            "example": 'filetype:docx "confidential contract"'
        },
        "databases": {
            "description": "Locate SQL dumps and databases",
            "dork": "filetype:sql | filetype:db | filetype:mdb",
            "example": 'filetype:sql "INSERT INTO" "password"'
        },
        "configuration_files": {
            "description": "Locate .env, .cfg, .conf, .ini, .yaml",
            "dork": 'filetype:env | filetype:cfg | filetype:conf | filetype:yaml',
            "example": 'filetype:env "DB_PASSWORD" -github'
        },
        "logs": {
            "description": "Locate exposed log files",
            "dork": "filetype:log | filetype:txt inurl:log",
            "example": 'filetype:log "error" "php" "warning"'
        },
        "backups": {
            "description": "Locate backup files (.bak, .zip, .tar, .gz)",
            "dork": 'filetype:bak | filetype:zip | filetype:tar | filetype:gz "backup"',
            "example": 'intitle:"index of" "backup.zip"'
        },
        "presentations": {
            "description": "Locate PowerPoint and similar",
            "dork": "filetype:pptx | filetype:ppt",
            "example": 'filetype:pptx "strategic planning"'
        },
        "source_code": {
            "description": "Locate exposed scripts and source code",
            "dork": "filetype:php | filetype:py | filetype:js | filetype:java",
            "example": 'filetype:php intext:"mysql_connect"'
        },
        "files_by_name": {
            "description": "Locate a file by exact name",
            "dork": 'intitle:"index of" "filename.ext"',
            "example": 'intitle:"index of" "wp-config.php"'
        }
    },

    # ============================================================
    # 2. FIND LOGIN PANELS / ADMIN PAGES
    # ============================================================
    "findPanels": {
        "generic_admin": {
            "description": "Generic administration panels",
            "dork": 'inurl:admin intitle:login',
            "example": 'site:target.com inurl:admin intitle:login'
        },
        "phpmyadmin": {
            "description": "Exposed phpMyAdmin panels",
            "dork": 'intitle:"phpMyAdmin" inurl:"/phpmyadmin"',
            "example": 'intitle:"phpMyAdmin" "Welcome to"'
        },
        "wordpress": {
            "description": "WordPress panels",
            "dork": 'inurl:/wp-admin | inurl:/wp-login.php',
            "example": 'site:target.com inurl:/wp-admin'
        },
        "cpanel": {
            "description": "cPanel/WHM panels",
            "dork": 'inurl:"/cpanel" | intitle:"cPanel"',
            "example": 'inurl:2083 intitle:login'
        },
        "joomla": {
            "description": "Joomla panels",
            "dork": 'inurl:/administrator intitle:"Joomla"',
            "example": 'site:target.com inurl:/administrator'
        },
        "drupal": {
            "description": "Drupal panels",
            "dork": 'inurl:/user/login intitle:"Log in"',
            "example": 'site:target.com inurl:/user/login'
        },
        "mikrotik": {
            "description": "Exposed MikroTik routers",
            "dork": 'intitle:"MikroTik RouterOS" inurl:webfig',
            "example": 'intitle:"RouterOS" "configuration"'
        },
        "webmin": {
            "description": "Webmin panels",
            "dork": 'intitle:"Webmin" inurl:10000',
            "example": 'intitle:"Login to Webmin"'
        },
        "jenkins": {
            "description": "Jenkins CI/CD servers",
            "dork": 'intitle:"Dashboard [Jenkins]"',
            "example": 'inurl:8080 intitle:"Jenkins"'
        },
        "gitlab": {
            "description": "GitLab instances",
            "dork": 'intitle:"Sign in · GitLab"',
            "example": 'inurl:/users/sign_in intitle:"GitLab"'
        }
    },

    # ============================================================
    # 3. FIND OPEN DIRECTORIES
    # ============================================================
    "findOpen_directories": {
        "general": {
            "description": "Any directory with listing enabled",
            "dork": 'intitle:"index of"',
            "example": 'intitle:"index of" /admin'
        },
        "ftp": {
            "description": "Exposed FTP directories",
            "dork": 'intitle:"index of" inurl:ftp',
            "example": 'intitle:"index of" inurl:ftp "pub"'
        },
        "backup": {
            "description": "Directories with backup files",
            "dork": 'intitle:"index of" "backup"',
            "example": 'intitle:"index of" "backup.sql"'
        },
        "uploads": {
            "description": "Exposed upload directories",
            "dork": 'intitle:"index of" inurl:uploads',
            "example": 'site:target.com intitle:"index of" inurl:uploads'
        },
        "wp_content": {
            "description": "Exposed WordPress wp-content directory",
            "dork": 'intitle:"index of" inurl:wp-content',
            "example": 'site:target.com intitle:"index of" /wp-content/uploads'
        },
        "exposed_git": {
            "description": "Exposed .git repositories",
            "dork": 'intitle:"index of" ".git"',
            "example": 'intitle:"index of" ".git/config"'
        },
        "credential_folders": {
            "description": "Directories with password/config files",
            "dork": 'intitle:"index of" "password" | "config" | "secret"',
            "example": 'intitle:"index of" "credentials.txt"'
        }
    },

    # ============================================================
    # 4. FIND SENSITIVE INFORMATION / LEAKS
    # ============================================================
    "findLeaks": {
        "credentials_in_txt": {
            "description": "Text files with credentials",
            "dork": 'filetype:txt "password" | "pass" | "login"',
            "example": 'filetype:txt intext:"password=" intext:"username="'
        },
        "api_keys": {
            "description": "Leaked API keys",
            "dork": 'filetype:env "API_KEY" | "TOKEN" | "SECRET" -github',
            "example": 'filetype:env "AWS_SECRET_ACCESS_KEY"'
        },
        "emails": {
            "description": "Exposed email lists",
            "dork": 'filetype:xlsx "@gmail.com" | "@hotmail.com"',
            "example": 'site:target.com filetype:csv "@"'
        },
        "ssn_id": {
            "description": "Documents with SSN/ID numbers",
            "dork": 'filetype:pdf "SSN" | "ID" "No."',
            "example": 'site:gov filetype:pdf "SSN" -template -example'
        },
        "credit_card": {
            "description": "Possible credit card leaks",
            "dork": 'filetype:txt "4111" | "5502" | "3400"',
            "example": 'filetype:log intext:"cvv" "expiration"'
        },
        "sql_credentials": {
            "description": "SQL dumps with user tables",
            "dork": 'filetype:sql "INSERT INTO" "users" "password"',
            "example": 'filetype:sql intext:"admin" intext:"hash"'
        },
        "internal_documents": {
            "description": "Documents marked as confidential",
            "dork": 'filetype:pdf "confidential" | "internal" | "restricted"',
            "example": 'site:company.com filetype:pdf "confidential"'
        },
        "pastebin_leaks": {
            "description": "Leaks posted on PasteBin",
            "dork": 'site:pastebin.com "company" "password"',
            "example": 'site:pastebin.com "company_name" "leak"'
        }
    },

    # ============================================================
    # 5. FIND DEVICES / IOT
    # ============================================================
    "findDevices": {
        "ip_cameras": {
            "description": "Exposed IP cameras",
            "dork": 'inurl:"view/viewer_index.shtml" | intitle:"webcam" inurl:8080',
            "example": 'intitle:"Live View" inurl:"/view/"'
        },
        "dvr_nvr": {
            "description": "Video recorders (DVR/NVR)",
            "dork": 'intitle:"DVR" inurl:login | intitle:"NVR"',
            "example": 'intitle:"DVR Login" -github'
        },
        "printers": {
            "description": "Exposed network printers",
            "dork": 'intitle:"HP" inurl:9100 | inurl:631 "printer"',
            "example": 'intitle:"LaserJet" inurl:"/hp/device"'
        },
        "routers": {
            "description": "Routers with web interface",
            "dork": 'intitle:"TP-Link" | intitle:"NETGEAR" | intitle:"D-Link"',
            "example": 'intitle:"TP-Link" inurl:admin'
        },
        "nas_storage": {
            "description": "NAS devices (Synology, QNAP)",
            "dork": 'intitle:"Synology" | intitle:"QNAP"',
            "example": 'intitle:"Synology DiskStation" inurl:5000'
        },
        "scada_ics": {
            "description": "Industrial SCADA/ICS systems",
            "dork": 'intitle:"PLC" | intitle:"SCADA" | intitle:"HMI"',
            "example": 'inurl:/Portal0000.htm intitle:"HMI"'
        }
    },

    # ============================================================
    # 6. FIND SPECIFIC VULNERABILITIES
    # ============================================================
    "findVulnerabilities": {
        "sql_injection": {
            "description": "Potentially injectable parameters",
            "dork": 'inurl:".php?id=" | inurl:".aspx?page=" | inurl:"?prod="',
            "example": 'site:target.com inurl:"?id=" inurl:".php"'
        },
        "xss": {
            "description": "Possible reflected XSS points",
            "dork": 'inurl:"?search=" | inurl:"&q=" | inurl:"?query="',
            "example": 'site:target.com inurl:"?search="'
        },
        "sql_error": {
            "description": "Exposed SQL error messages",
            "dork": 'intext:"you have an error in your sql syntax"',
            "example": 'intext:"mysql_fetch_array" intext:"warning"'
        },
        "php_info": {
            "description": "Exposed phpinfo() pages",
            "dork": 'intitle:"phpinfo()" "PHP Version"',
            "example": 'ext:php intitle:"phpinfo"'
        },
        "debug_mode": {
            "description": "Debug mode enabled in production",
            "dork": 'intext:"debug" intext:"true" filetype:env',
            "example": 'intext:"APP_DEBUG=true" filetype:env'
        },
        "software_version": {
            "description": "Specific software versions (fingerprinting)",
            "dork": 'intitle:"Apache2 Ubuntu Default Page"',
            "example": 'intitle:"Apache Status" "Server Version"'
        },
        "open_redirect": {
            "description": "Possible redirect parameters",
            "dork": 'inurl:"?redirect=" | inurl:"?url=" | inurl:"?return="',
            "example": 'site:target.com inurl:"?redirect=http"'
        },
        "local_file_inclusion": {
            "description": "Possible LFI points",
            "dork": 'inurl:"?file=" | inurl:"?page=" | inurl:"?path="',
            "example": 'site:target.com inurl:"?page=" ext:php'
        }
    },

    # ============================================================
    # 7. INTELLIGENCE / OSINT / RECONNAISSANCE
    # ============================================================
    "intelligenceOsint": {
        "subdomains": {
            "description": "Discover subdomains of a target",
            "dork": "site:*.domain.com -www",
            "example": "site:*.gov -www -mail"
        },
        "linkedin_employees": {
            "description": "Find employee profiles",
            "dork": 'site:linkedin.com/in "company" "position"',
            "example": 'site:linkedin.com/in "Google" "software engineer"'
        },
        "government_documents": {
            "description": "Documents on .gov sites",
            "dork": 'site:gov filetype:pdf "contract"',
            "example": 'site:gov filetype:pdf "contract" "value"'
        },
        "academic_documents": {
            "description": "Theses and research on .edu sites",
            "dork": 'site:edu filetype:pdf "thesis" | "dissertation"',
            "example": 'site:edu filetype:pdf "artificial intelligence"'
        },
        "target_technologies": {
            "description": "Identify technologies used",
            "dork": 'site:target.com "powered by" | "built with"',
            "example": 'site:target.com intext:"wp-content"'
        },
        "robots_txt": {
            "description": "Read robots.txt from a site via cache",
            "dork": "cache:target.com/robots.txt",
            "example": "cache:company.com/robots.txt"
        },
        "sitemap": {
            "description": "Find indexed sitemaps",
            "dork": 'site:target.com filetype:xml inurl:sitemap',
            "example": 'site:company.com inurl:sitemap.xml'
        },
        "web_archive": {
            "description": "View old versions of pages (need to access archive.org afterwards)",
            "dork": 'cache:target.com/old-page',
            "example": "cache:company.com/team (removed employee page)"
        }
    },

    # ============================================================
    # 8. ADVANCED OPERATOR SEARCHES
    # ============================================================
    "advancedTechniques": {
        "word_proximity": {
            "description": "Find words close together (context)",
            "dork": '"word1" AROUND(N) "word2"',
            "example": '"password" AROUND(5) "admin" filetype:txt'
        },
        "specific_date": {
            "description": "Results before/after a date",
            "dork": "before:YYYY-MM-DD | after:YYYY-MM-DD",
            "example": 'site:target.com "leak" after:2024-01-01'
        },
        "numeric_range": {
            "description": "Search by number range (IPs, ports)",
            "dork": "number1..number2",
            "example": 'intext:"192.168.1." 1..254'
        },
        "multiple_exclusion": {
            "description": "Remove false positives from search",
            "dork": "-term1 -term2 -term3",
            "example": 'intitle:"index of" -github -stackoverflow -gitlab'
        },
        "logical_grouping": {
            "description": "Combine multiple operators with logic",
            "dork": "site:target.com inurl:(admin | login | dashboard) intitle:(login | panel | access)",
            "example": 'site:gov filetype:(pdf | xlsx | docx) "contract"'
        },
        "powerful_combination": {
            "description": "Multi-operator dork for precise search",
            "dork": 'site:target.com filetype:pdf intitle:"report" intext:"confidential" after:2023-01-01 -template -example',
            "example": 'site:company.com filetype:env "DB_PASSWORD" -github -gitlab -bitbucket'
        }
    },

    # ============================================================
    # 9. FIND INFRASTRUCTURE RESOURCES
    # ============================================================
    "infrastructure": {
        "s3_buckets_aws": {
            "description": "Exposed Amazon S3 buckets",
            "dork": 'site:s3.amazonaws.com "Company Name"',
            "example": 'site:s3.amazonaws.com "backup" "db"'
        },
        "kubernetes": {
            "description": "Kubernetes configuration files",
            "dork": 'filetype:yaml "kind: Config" | "kubeconfig"',
            "example": 'filetype:yaml "apiVersion: v1" "token"'
        },
        "docker": {
            "description": "Dockerfile and docker-compose files",
            "dork": 'filetype:yml "docker-compose" | filetype:yaml "services:"',
            "example": 'filetype:yml intext:"image:" intext:"ports:"'
        },
        "terraform": {
            "description": "Terraform files with state",
            "dork": 'filetype:tf "terraform" | filetype:tfstate',
            "example": 'filetype:tfstate "aws_access_key"'
        },
        "jenkinsfile": {
            "description": "Exposed Jenkins pipelines",
            "dork": 'filetype:jenkinsfile | intitle:"Jenkinsfile"',
            "example": 'filetype:groovy intext:"pipeline" intext:"agent"'
        },
        "ssh_keys": {
            "description": "Exposed private SSH keys",
            "dork": 'filetype:pem "PRIVATE KEY" | filetype:ppk',
            "example": 'intitle:"index of" "id_rsa" -github'
        }
    }
}