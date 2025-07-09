from modules import recon, dir_enum, static_analyzer, vuln_scan

def run(root_url, full_url):
    print("==========[ 🔁 전체 자동 실행 시작 ]==========")

    try:
        print("\n[1] 정찰(정보 수집)")
        recon.run(root_url)
    except Exception as e:
        print(f"[!] recon 에러: {e}")

    try:
        print("\n[2] 디렉토리/파일 탐색 + 403 우회")
        dir_enum.run(root_url)
    except Exception as e:
        print(f"[!] dir_enum 에러: {e}")

    try:
        print("\n[3] JS/CSS 정적 파일 분석")
        static_analyzer.run(root_url)
    except Exception as e:
        print(f"[!] static_analyzer 에러: {e}")

    try:
        print("\n[4] 취약점 테스트 (XSS, SQLi, CSRF, SSRF, SSTI)")
        vuln_scan.run(full_url)
    except Exception as e:
        print(f"[!] vuln_scan 에러: {e}")

    print("\n==========[ ✅ 전체 자동화 완료 ]==========")
