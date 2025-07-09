import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.results_manager import save_result, logging

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "apikey", "token", "auth", "key", "url"
]

VULN_LIBS = {
    "jquery": {
        "regex": r"jquery[-.]?(\d+\.\d+(\.\d+)?)\.js",
        "vuln_versions": ["1.7", "1.8", "1.9", "1.10", "1.11", "2.1", "3.0"]
    },
    "angular": {
        "regex": r"angular[-.]?(\d+\.\d+(\.\d+)?)\.js",
        "vuln_versions": ["1.2", "1.3", "1.4", "1.5", "1.6"]
    }
}

MAX_DEPTH = 2

def analyze_content(html, source_url):
    result = {"url": source_url, "sensitive_keywords": [], "vulnerable_libs": []}

    lower_html = html.lower()
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in lower_html:
            result["sensitive_keywords"].append(keyword)

    for lib, info in VULN_LIBS.items():
        match = re.search(info["regex"], source_url, re.I)
        if match:
            version = match.group(1)
            if any(version.startswith(v) for v in info["vuln_versions"]):
                result["vulnerable_libs"].append({"library": lib, "version": version})

    return result

def fetch_url(url):
    try:
        res = requests.get(url, timeout=5)
        return url, res
    except Exception as e:
        logging.error(f"Request error: {url} - {e}")
        return url, None

def crawl(base_domain, url, depth, visited, results):
    if url in visited or depth > MAX_DEPTH:
        return
    visited.add(url)

    url, res = fetch_url(url)
    if not res:
        return

    content_analysis = analyze_content(res.text, url)
    results.append(content_analysis)

    soup = BeautifulSoup(res.text, "lxml")
    links = set()

    for tag in soup.find_all(["a", "script", "link"]):
        link = tag.get("href") or tag.get("src")
        if link:
            full_url = urljoin(url, link).split('#')[0]
            if urlparse(full_url).netloc == base_domain:
                links.add(full_url)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(crawl, base_domain, link, depth + 1, visited, results) for link in links]
        for _ in as_completed(futures):
            pass  # 작업 완료 대기

def run(target_url):
    parsed = urlparse(target_url)
    base_domain = parsed.netloc
    visited = set()
    results = []

    print(f"[*] 탐색 시작: {target_url} (최대 깊이: {MAX_DEPTH})")

    crawl(base_domain, target_url.rstrip('/'), 0, visited, results)

    save_result("static_analyzer", results)
