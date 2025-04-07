# Nuclei-AI-Prompts
1️⃣ Recon
```
> docker run -v $(pwd):/src projectdiscovery/subfinder:latest -dL /src/domains -silent -o /src/subdomains
> docker run -v $(pwd):/src projectdiscovery/dnsx:latest -l /src/subdomains -t 500 -retry 5 -silent -o /src/dnsx
> docker run -v $(pwd):/src projectdiscovery/naabu:latest -l /src/dnsx -tp 1000 -ec -c 100 -rate 5000 -o /src/alive_ports
> docker run -v $(pwd):/src projectdiscovery/httpx:latest -l /src/alive_ports -t 100 -rl 500 -o /src/targets.txt
```
2️⃣ Recon (Active Crawl Links)
```
katana -l targets.txt -aff -j -o katana.jsonl
```
3️⃣ Recon (Active + Passive JS Links)
```
docker run -v $(pwd):/src secsi/getjs --input /src/targets.txt --complete --output /src/js_links
katana -u targets.txt -ps -em js,json >> js_links # katana version 1.1.0
```
# Fast Info Gathering
```
nuclei -list targets.txt -ai "Extract page title, detech tech and versions"
nuclei -list targets.txt -ai "Extract email addresses from web pages"
nuclei -list targets.txt -ai "Extract all subdomains referenced in web pages"
```
# Low Hanging Fruits
```
nuclei -list targets.txt -ai "Find sensitive information in HTML comments (debug notes, API keys, credentials)"
nuclei -list targets.txt -ai "Find exposed .env files leaking credentials, API keys, and database passwords"
nuclei -list targets.txt -ai "Find exposed configuration files such as config.json, config.yaml, config.php, application.properties containing API keys and database credentials."
nuclei -list targets.txt -ai "Find exposed configuration files containing sensitive information such as credentials, API keys, database passwords, and cloud service secrets."  
nuclei -list targets.txt -ai "Find database configuration files such as database.yml, db_config.php, .pgpass, .my.cnf leaking credentials."  
nuclei -list targets.txt -ai "Find exposed Docker and Kubernetes configuration files such as docker-compose.yml, kubeconfig, .dockercfg, .docker/config.json containing cloud credentials and secrets."  
nuclei -list targets.txt -ai "Find exposed SSH keys and configuration files such as id_rsa, authorized_keys, and ssh_config."  
nuclei -list targets.txt -ai "Find exposed WordPress configuration files (wp-config.php) containing database credentials and authentication secrets."  
nuclei -list targets.txt -ai "Identify exposed .npmrc and .yarnrc files leaking NPM authentication tokens"
nuclei -list targets.txt -ai "Identify open directory listings exposing sensitive files"  
nuclei -list targets.txt -ai "Find exposed .git directories allowing full repo download"
nuclei -list targets.txt -ai "Find exposed .svn and .hg repositories leaking source code"  
nuclei -list targets.txt -ai "Identify open FTP servers allowing anonymous access"  
nuclei -list targets.txt -ai "Find GraphQL endpoints with introspection enabled"  
nuclei -list targets.txt -ai "Identify exposed .well-known directories revealing sensitive data"  
nuclei -list targets.txt -ai "Find publicly accessible phpinfo() pages leaking environment details"  
nuclei -list targets.txt -ai "Find exposed Swagger, Redocly, GraphiQL, and API Blueprint documentation"  
nuclei -list targets.txt -ai "Identify exposed .vscode and .idea directories leaking developer configs"  
nuclei -list targets.txt -ai "Detect internal IP addresses (10.x.x.x, 192.168.x.x, etc.) in HTTP responses"  
nuclei -list targets.txt -ai "Find exposed WordPress debug.log files leaking credentials and error messages"  
nuclei -list targets.txt -ai "Detect misconfigured CORS allowing wildcard origins ('*')"  
nuclei -list targets.txt -ai "Find publicly accessible backup and log files (.log, .bak, .sql, .zip, .dump)"  
nuclei -list targets.txt -ai "Find exposed admin panels with default credentials"
nuclei -list targets.txt -ai "Identify commonly used API endpoints that expose sensitive user data, returning HTTP status 200 OK."
nuclei -list targets.txt -ai "Detect web applications running in debug mode, potentially exposing sensitive system information."  
```

# Advanced Mixed Testing
```
nuclei -list targets.txt -ai "Detect debug endpoints revealing system information"  
nuclei -list targets.txt -ai "Identify test and staging environments exposed to the internet"  
nuclei -list targets.txt -ai "Find admin login endpoints, filter 404 response code"
nuclei -list targets.txt -ai "Find misconfigured CORS policies allowing wildcard origins"
nuclei -list targets.txt -ai "Detect exposed stack traces in error messages"
nuclei -list targets.txt -ai "Identify default credentials on login pages"
nuclei -list targets.txt -ai "Find misconfigured Apache/Nginx security headers"  
nuclei -list targets.txt -ai "Check for APIs allowing unauthenticated access to admin routes"  
nuclei -list targets.txt -ai "Identify exposed admin panels of popular CMS (WordPress, Joomla, etc.)"
```
# Sensitive Data Exposure
```
nuclei -list targets.txt -ai "Scan for exposed environment files (.env) containing credentials"
nuclei -list targets.txt -ai "Find open directory listings and publicly accessible files"
nuclei -list targets.txt -ai "Detect exposed .git repositories and sensitive files"
nuclei -list targets.txt -ai "Identify publicly accessible backup and log files (.log, .bak, .sql, .dump)"
nuclei -list targets.txt -ai "Detect exposed .htaccess and .htpasswd files"
nuclei -list targets.txt -ai "Check for SSH private keys leaked in web directories"
nuclei -list targets.txt -ai "Find exposed API keys and secrets in responses and URLs"
nuclei -list targets.txt -ai "Identify API endpoints leaking sensitive data"
nuclei -list targets.txt -ai "Find leaked database credentials in JavaScript files"
nuclei -list targets.txt -ai "Scan for hardcoded credentials in source code comments"
nuclei -list targets.txt -ai "Identify sensitive endpoints leaking personal or internal data"
nuclei -list targets.txt -ai "Detect vulnerable API endpoints exposing user input or sensitive information"
nuclei -list targets.txt -ai "Find exposed server status pages (e.g., phpinfo, server-status)"
nuclei -list targets.txt -ai "Identify sensitive configuration files (.env, .config, application.properties, settings.py)"
nuclei -list targets.txt -ai "Scan for information leaks in HTTP responses and headers"
```
# Sensitive Data Exposure (Javascript Files)
```
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Analyze JavaScript code for security vulnerabilities (XSS, CSRF, CORS misconfigurations, Clickjacking)"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Perform a full deep JavaScript security audit: API keys, secrets, internal endpoints, debug logs, authentication tokens, and misconfigurations"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find hardcoded API keys, JWT tokens, OAuth credentials, and authentication secrets in JavaScript"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Identify hardcoded cloud service credentials (AWS, GCP, Azure) in JavaScript files"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find internal API endpoints (REST, GraphQL, WebSockets) hidden in JavaScript files"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect API keys, JWT tokens, and passwords in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find AWS, Google Cloud, and Azure API keys exposed in JavaScript"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect OAuth, Facebook, Twitter, and Google API tokens in JavaScript files"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find Firebase, MongoDB, and Elasticsearch credentials in JavaScript"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect hardcoded JWT tokens and secrets in JavaScript files"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Identify exposed payment API keys for Stripe, PayPal, and Square in JavaScript files"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find debugging logs, internal API endpoints, and test credentials in JavaScript"  
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Detect corporate email addresses, internal contacts and internal resource in JavaScript files"
docker run -v $(pwd):/src projectdiscovery/nuclei:latest -l /src/js_links -ai "Find exposed JavaScript source maps (.map files) revealing original source code"
```

# SQL Injection (SQLi)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SQL Injection vulnerabilities with pre-conditions."
nuclei -list katana.jsonl -im jsonl -ai "Detect SQL error messages indicating SQL injection vulnerabilities"
nuclei -list katana.jsonl -im jsonl -ai "Detect SQL errors in response when injecting common payloads into GET and POST requests"  
nuclei -list katana.jsonl -im jsonl -ai "Find SQL injection in 'id', 'user', 'product', 'category', 'page' parameters"  
nuclei -list katana.jsonl -im jsonl -ai "Scan for blind SQL injection in 's', 'search', 'query', 'sort', 'filter' GET/POST parameters"
nuclei -list katana.jsonl -im jsonl -ai "Scan for time based SQL injection in all parameters" 
nuclei -list katana.jsonl -im jsonl -ai "Identify SQL injection in API endpoints using JSON payloads"  
nuclei -list katana.jsonl -im jsonl -ai "Check for SQL injection via HTTP headers (User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host)" 
```
# Cross-Site Scripting (XSS)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting XSS vulnerabilities (Reflected, Stored, and DOM-based) with pre-conditions."
nuclei -list katana.jsonl -im jsonl -ai "Find reflected XSS in 'q', 'search', 's', 'redirect', 'next', 'return', 'url' parameters"
nuclei -list katana.jsonl -im jsonl -ai "Find stored XSS in all parameters"
nuclei -list katana.jsonl -im jsonl -ai "Identify stored XSS in comment fields, usernames, profile descriptions"  
nuclei -list katana.jsonl -im jsonl -ai "Detect DOM-based XSS in JavaScript variables using common sources like location.href"  
nuclei -list katana.jsonl -im jsonl -ai "Scan for XSS vulnerabilities in AJAX endpoints"  
nuclei -list katana.jsonl -im jsonl -ai "Check for JSON-based XSS via API responses"
nuclei -list katana.jsonl -im jsonl -ai "Identify reflected cross-site scripting (XSS) vulnerabilities"
```
# Server-Side Request Forgery (SSRF)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting SSRF vulnerabilities with pre-conditions."
nuclei -list katana.jsonl -im jsonl -ai "Find SSRF vulnerabilities in web applications"
nuclei -list katana.jsonl -im jsonl -ai "Identify SSRF vulnerabilities in query parameters"
nuclei -list katana.jsonl -im jsonl -ai "Identify SSRF vulnerabilities in most common parameters"
nuclei -list katana.jsonl -im jsonl -ai "Find SSRF in 'url', 'link', 'redirect', 'next', 'feed', 'callback' parameters"
nuclei -list katana.jsonl -im jsonl -ai "Detect SSRF by injecting internal IP ranges (127.0.0.1, 169.254.169.254)"
nuclei -list katana.jsonl -im jsonl -ai "Identify SSRF in API requests that fetch external resources"
nuclei -list katana.jsonl -im jsonl -ai "Scan for blind SSRF by injecting webhooks and external DNS resolver payloads"
```
# Local & Remote File Inclusion (LFI/RFI)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting LFI/RFI vulnerabilities with pre-conditions."
nuclei -list katana.jsonl -im jsonl -ai "Find LFI in 'file', 'path', 'template', 'inc', 'lang', 'page' parameters"
nuclei -list katana.jsonl -im jsonl -ai "Detect RFI by injecting external URLs into 'file' and 'load' parameters"
nuclei -list katana.jsonl -im jsonl -ai "Identify LFI using common payloads (/etc/passwd, ../../etc/passwd, php://filter, php://input)"
nuclei -list katana.jsonl -im jsonl -ai "Check for LFI in error messages exposing full file paths"
```
# Command Injection (RCE)
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting Remote Code Execution (Command Injection) vulnerabilities with pre-conditions."
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all parameters and HTTP methods using DSL, focusing on detecting Remote Code Execution (RCE) vulnerabilities on Linux and Windows."
nuclei -list katana.jsonl -im jsonl -ai "Detect command injection in 'cmd', 'exec', 'ping', 'query', 'shell' parameters"
nuclei -list katana.jsonl -im jsonl -ai "Scan for OS command injection via HTTP headers (X-Forwarded-For, X-Forwarded-Host, User-Agent, Referer)"
nuclei -list katana.jsonl -im jsonl -ai "Identify RCE vulnerabilities in file upload functionalities"
```
# XXE
```
nuclei -list katana.jsonl -im jsonl -ai "Perform fuzzing on all XML-based inputs using DSL, focusing on detecting XXE vulnerabilities with pre-conditions."  
```
# Host Header Injection
```
nuclei -l targets.txt -ai "Detect Host Header Injection" 
```
# Cloud Security Issues
```
nuclei -list targets.txt -ai "Detect open Docker API endpoints allowing remote access"
nuclei -list targets.txt -ai "Detect exposed Kubernetes API servers allowing unauthenticated access"
nuclei -list targets.txt -ai "Find open Kubernetes Dashboard instances with weak or no authentication"
nuclei -list targets.txt -ai "Detect exposed Kubernetes dashboards and APIs"
nuclei -list targets.txt -ai "Scan for cloud metadata endpoints accessible externally"
nuclei -list targets.txt -ai "Detect AWS S3, GCP, Azure buckets in response, and scan this cloud storage buckets (AWS S3, GCP, Azure) for misconfigurations (read, write ACL, public access, etc)"
nuclei -list targets.txt -ai "Detect Azure Storage Account keys exposed in responses, minimize false positive"
nuclei -list targets.txt -ai "Detect AWS keys exposed in responses and write extractors, minimize false positive"
nuclei -list targets.txt -ai "Detect GCP keys exposed in responses and write extractors, minimize false positive"
```
# Web Cache Poisoning
```
nuclei -list targets.txt -ai "Find web cache poisoning via 'Host", 'X-Forwarded-Host' and'X-Forwarded-For' headers, provide additional vulnerability checking (second/third request)"
nuclei -list targets.txt -ai "Detect cache poisoning through 'X-Original-URL' and 'X-Rewrite-URL' headers, provide additional vulnerability checking (second/third request)"
nuclei -list targets.txt -ai "Identify cache poisoning by injecting payloads in 'Referer' and 'User-Agent', provide additional vulnerability checking (second/third request)"
nuclei -list targets.txt -ai "Scan for cache poisoning via malformed HTTP headers, provide additional vulnerability checking (second/third request)"
nuclei -list targets.txt -ai "Detect cache poisoning vulnerabilities on Fastly and Cloudflare, provide additional vulnerability checking (second/third request)"
nuclei -list targets.txt -ai "Find misconfigured Varnish caching rules exposing private data, provide additional vulnerability checking (second/third request)"
nuclei -list targets.txt -ai "Identify Squid proxy cache poisoning vulnerabilitie, provide additional vulnerability checking (second/third request)"
```
