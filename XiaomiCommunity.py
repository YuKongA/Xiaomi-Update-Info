#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, json, time, base64, binascii, hashlib

from sys import argv


# 获取Cookie
def login(account, password):
    md5 = hashlib.md5()
    md5.update(password.encode())
    Hash = md5.hexdigest()
    sha1 = hashlib.sha1()
    url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
    data = {
        "_json": "true",
        "bizDeviceType": "",
        "user": account,
        "hash": Hash.upper(),
        "sid": "miuiromota",
        "_sign": "L+dSQY6sjSQ/CRjJs4p+U1vNYLY=",
        "_locale": "zh_CN",
    }
    response = requests.post(url=url, data=data).text.lstrip("&").lstrip("START").lstrip("&")
    cookies_data = json.dumps(response, ensure_ascii=False, allow_nan=True)
    with open("response.json", "w", encoding="utf-8") as file:
        file.write(response)
    Auth = json.loads(response)
    if Auth["description"] != "成功":
        return "Error"
    sha1.update(
        ("nonce=" + str(Auth["nonce"]) + "&" + Auth["ssecurity"]).encode("utf-8")
    )
    clientSign = (
        base64.encodebytes(binascii.a2b_hex(sha1.hexdigest().encode("utf-8")))
        .decode(encoding="utf-8")
        .strip()
    )
    nurl = Auth["location"] + "&_userIdNeedEncrypt=true&clientSign=" + clientSign
    cookies_dict = requests.utils.dict_from_cookiejar(requests.get(url=nurl).cookies)
    cookies_data = json.dumps(cookies_dict, ensure_ascii=False, allow_nan=True)
    with open("cookies.json", "w", encoding="utf-8") as file:
        file.write(cookies_data)
    return cookies_dict


# 使用提示
def usage():
    print("\nUsage: XiaomiCommunity.py account password\n")
    exit()


# 主程序
def main():
    if len(argv) < 3:
        usage()
    account = argv[1]
    password = argv[2]
    for i in range(5):
        cookie = login(account, password)
        if len(cookie) != 0:
            break
        else:
            time.sleep(i)
    if len(cookie) == 0 or cookie == "Error":
        print(f"{account}：登录失败")
    else:
        print(f"{account}：登录成功")
        return


if __name__ == "__main__":
    main()
