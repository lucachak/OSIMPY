# 🛡️ OSINPY — Advanced OSINT & Google Dorking Suite

> **OSINPY** é uma ferramenta profissional e de alta performance voltada para automação de **Google Dorking** e inteligência de fontes abertas (OSINT). Desenvolvida sob uma arquitetura totalmente assíncrona, a suite permite realizar varreduras em massa, identificar vulnerabilidades de exposição, vazar credenciais expostas e extrair arquivos confidenciais de forma extremamente rápida e robusta.

---

## 🚀 Principais Recursos

- **Arquitetura 100% Assíncrona (`asyncio`)**: Execução de loops paralelos velozes, garantindo que buscas e downloads concorrentes ocorram em tempo recorde sem bloquear a execução.
- **Bypass de CAPTCHA Inteligente (Fallback em 4 Níveis)**:
  1. 🌐 `nodriver`: Navegador Chromium real e automatizado (invisível à automação controlada).
  2. 🦆 `duckduckgo`: Busca textual leve e eficiente.
  3. 🔍 `google`: Requisições HTTP diretas via urllib.
  4. 🎯 `yahoo`: Extrator orgânico inteligente capaz de desviar de CAPTCHAs agressivos analisando redirecionamentos de busca orgânica.
- **Downloader Paralelo Avançado**:
  - Salve arquivos diretamente em um diretório personalizado usando a opção `-d` ou `--download-dir`.
  - Cabeçalhos HTTP realistas que mimetizam o Google Chrome para desviar de bloqueios de Firewalls corporativos (WAFs) que geram erros `403 Forbidden`.
- **Exportação Estruturada**: Salvamento automático de links orgânicos, títulos e trechos (snippets) estruturados em JSON legível no diretório de saída `/output/`.

---

## 📁 Categorias de Busca Suportadas (1 a 9)

O OSINPY vem pré-configurado com dorks avançadas organizadas em 9 categorias principais em seu banco de dados (`helpers/manual.py`):

1. **`findFiles`**: Encontre arquivos de dados expostos (`pdfs`, `word_documents`, `spreadsheets`, `databases`, `backups`, `logs`, `source_code`, etc.).
2. **`findPanels`**: Identifique painéis administrativos e portas de entrada (`generic_admin`, `phpmyadmin`, `cpanel`, `webmail`).
3. **`findOpen_directories`**: Localize diretórios expostos indexados pelo servidor (`general`, `backup_folders`, `sensitive_data`).
4. **`findLeaks`**: Encontre credenciais, tokens e chaves de API expostas (`credentials_in_txt`, `api_keys`, `env_files`, `sql_dumps`).
5. **`findDevices`**: Mapeie dispositivos IoT e hardware conectado à rede (`ip_cameras`, `routers`, `printers`).
6. **`findVulnerabilities`**: Localize brechas de segurança comuns (`php_info`, `sql_errors`, `xss_endpoints`).
7. **`intelligenceOsint`**: Coleta de inteligência organizacional (`academic_documents`, `employee_bios`, `org_charts`).
8. **`advancedTechniques`**: Combinações altamente refinadas de dorks complexas (`powerful_combination`, `rapid_scan`).
9. **`infrastructure`**: Identificação de ativos em nuvem e DevOps expostos (`s3_buckets_aws`, `kubernetes`, `jenkins_dashboards`).

---

## 🛠️ Instalação e Requisitos

### Pré-requisitos
- Python 3.12 ou superior (Totalmente compatível e testado no **Python 3.14**)
- Navegador Google Chrome/Chromium instalado (para execução do motor `nodriver`)

### Instalação rápida

1. Clone ou inicialize o diretório do projeto:
   ```bash
   git init
   ```
2. Crie e ative um ambiente virtual:
   ```bash
   python -m venv .venv
   source .venv/bin/browser
   # No Linux/MacOS:
   source .venv/bin/activate
   ```
3. Instale as dependências requeridas:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🎯 Exemplos Práticos de Uso

### 1. Busca Simples com Download Automático
Busque por arquivos PDF de relatórios financeiros expostos em domínios brasileiros (`.com.br`) salvando os PDFs diretamente em uma pasta customizada:
```bash
python main.py auto findFiles pdfs --filter .com.br --query "financial report" --download-dir relatorios_financeiros --max-results 5
```

### 2. Identificação de Diretórios Abertos (.edu)
Localize listagens de diretórios contendo cursos em universidades públicas usando o motor resiliente do Yahoo:
```bash
python main.py yahoo findOpen_directories general --filter .edu --query "courses" --max-results 10
```

### 3. Varredura Headless Silenciosa de Vulnerabilidades (phpinfo)
Realize uma busca em segundo plano (headless) sem abrir visualmente a janela do navegador por arquivos `phpinfo` expostos:
```bash
python main.py nodriver findVulnerabilities php_info --filter .gov --headless --max-results 3
```

---

## 🏗️ Estrutura do Repositório

```text
OSINPY/
├── helpers/
│   ├── Crawler.py      # Motores de crawler assíncronos e downloader paralelo
│   ├── Executor.py     # Interpretador de categorias e montador de templates de dork
│   └── manual.py       # Banco de dorks e dicionários configurados por categoria
├── output/             # Logs JSON salvos automaticamente das execuções (Ignorado pelo Git)
├── downloads/          # Pasta padrão de downloads (Ignorado pelo Git)
├── main.py             # Interface de linha de comando (CLI) principal
├── .gitignore          # Configuração de arquivos ignorados do Git
└── README.md           # Esta documentação
```

---

## ⚖️ Aviso Legal / Disclaimer

> **AVISO IMPORTANTE:** Esta ferramenta foi desenvolvida estritamente para fins de auditoria de segurança cibernética acadêmica e testes de invasão autorizados (Pentesting). O uso desta ferramenta para realizar buscas e coletar informações de sistemas sem autorização prévia por escrito é de inteira e exclusiva responsabilidade do usuário. O desenvolvedor não assume qualquer responsabilidade por uso indevido, danos colaterais ou ações legais decorrentes do uso inadequado deste software.
