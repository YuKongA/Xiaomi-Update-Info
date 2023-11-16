#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, json, time, base64, binascii, hashlib, random

from sys import argv
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


# 随机字符
def random_str(length):
    s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()-=_+~`{}[]|:<>?/."
    return "".join(random.choice(s) for _ in range(length))


# AES加密
def aes_encrypt(key, data):
    iv = "0102030405060708".encode("utf-8")
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv)
    padded_data = pad(data.encode("utf-8"), AES.block_size, style="pkcs7")
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode("utf-8")


# RSA加密
def rsa_encrypt(key, data):
    public_key = RSA.import_key(key)
    cipher = PKCS1_v1_5.new(public_key)
    ciphertext = cipher.encrypt(base64.b64encode(data.encode("utf-8")))
    return base64.b64encode(ciphertext).decode("utf-8")


# 获取Token
def get_token():
    key = random_str(16)
    public_key = """-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArxfNLkuAQ/BYHzkzVwtu
    g+0abmYRBVCEScSzGxJIOsfxVzcuqaKO87H2o2wBcacD3bRHhMjTkhSEqxPjQ/FE
    XuJ1cdbmr3+b3EQR6wf/cYcMx2468/QyVoQ7BADLSPecQhtgGOllkC+cLYN6Md34
    Uii6U+VJf0p0q/saxUTZvhR2ka9fqJ4+6C6cOghIecjMYQNHIaNW+eSKunfFsXVU
    +QfMD0q2EM9wo20aLnos24yDzRjh9HJc6xfr37jRlv1/boG/EABMG9FnTm35xWrV
    R0nw3cpYF7GZg13QicS/ZwEsSd4HyboAruMxJBPvK3Jdr4ZS23bpN0cavWOJsBqZ
    VwIDAQAB
    -----END PUBLIC KEY-----"""
    data = (
        '{"type":0,"startTs":'
        + str(round(time.time() * 1000))
        + ',"endTs":'
        + str(round(time.time() * 1000))
        + ',"env":{"p1":"","p2":"","p3":"","p4":"","p5":"","p6":"","p7":"","p8":"","p9":"","p10":"","p11":"","p12":"","p13":"","p14":"","p15":"","p16":"","p17":"","p18":"","p19":5,"p20":"","p21":"","p22":5,"p23":"","p24":"","p25":"","p26":"","p28":"","p29":"","p30":"","p31":"","p32":"","p33":"","p34":""},"action":{"a1":[],"a2":[],"a3":[],"a4":[],"a5":[],"a6":[],"a7":[],"a8":[],"a9":[],"a10":[],"a11":[],"a12":[],"a13":[],"a14":[]},"force":false,"talkBack":false,"uid":"'
        + random_str(27)
        + '","nonce":{"t":'
        + str(round(time.time()))
        + ',"r":'
        + str(round(time.time()))
        + '},"version":"2.0","scene":"GROW_UP_CHECKIN"}'
    )
    s = rsa_encrypt(public_key, key)
    d = aes_encrypt(key, data)
    url = "https://verify.sec.xiaomi.com/captcha/v2/data?k=3dc42a135a8d45118034d1ab68213073&locale=zh_CN"
    data = {"s": s, "d": d, "a": "GROW_UP_CHECKIN"}
    result = requests.post(url=url, data=data).json()
    if result["msg"] != "参数错误":
        return result["data"]["token"]


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
