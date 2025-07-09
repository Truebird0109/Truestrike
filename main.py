from modules import recon, dir_enum, static_analyzer, vuln_scan, full_auto
from urllib.parse import urlparse, urlunparse

def menu():
    user_input_url = input("[+] 대상 URL 입력 (쿼리 파라미터 포함 가능): ").strip()

    parsed_url = urlparse(user_input_url)
    root_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))

    while True:
        print("\n[메뉴 선택]")
        print("1) 정찰(정보 수집)")
        print("2) 디렉토리/파일 탐색 + 403 우회")
        print("3) JS/CSS 분석")
        print("4) 취약점 테스트 (XSS, SQLi 등)")
        print("5) 전체 자동 실행")
        print("6) 종료")

        choice = input(">> 실행할 번호 선택: ").strip()

        if choice == "1":
            recon.run(root_url)
        elif choice == "2":
            dir_enum.run(root_url)
        elif choice == "3":
            static_analyzer.run(root_url)
        elif choice == "4":
            vuln_scan.run(user_input_url)
        elif choice == "5":
            full_auto.run(root_url, user_input_url)
        elif choice == "6":
            print("👋 종료합니다.")
            break
        else:
            print("❌ 잘못된 선택입니다. 1~6번 중에서 선택하세요.")

if __name__ == "__main__":
    menu()
