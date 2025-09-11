#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64, json, re, requests, os, argparse, binascii, hashlib, getpass, sys, random, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib.parse import urlparse, parse_qs


# 尝试导入必要的模块
try:
    from Crypto.Cipher import ARC4
except ModuleNotFoundError:
    try:
        from Cryptodome.Cipher import ARC4
    except ModuleNotFoundError:
        pass  # ARC4 可能不用于核心功能

try:
    from PIL import Image
    from colorama import Fore, Style, init
except ModuleNotFoundError:
    pass  # 这些模块是可选的，用于验证码显示


# 常量
MIUI_UPDATE_URL = "https://update.miui.com/updates/miotaV3.php"
LOGININ_URL1 = "https://account.xiaomi.com/pass/serviceLogin"
LOGININ_URL2 = "https://account.xiaomi.com/pass/serviceLoginAuth2"
IV = b"0102030405060708"


# 生成上传数据
def generate_json(device, version, android, userId):
    data = {  # After testing, the commented out parts do not need to be assigned values.
        # "obv": "OS1.0", # ro.mi.os.version.name
        # "channel":"",  # Unknown
        # "sys": "0",  # Unknown
        # "bv": "816",  # bigversion
        "id": userId,  # userId
        # "sn": "0x0000000000000000",  # SN
        # "a": "0",  # Unknown
        # "b": "F" if "DEV" not in version else "X",  # MIUI branch
        "c": android,  # android version Build.VERSION.RELEASE
        # "unlock": "0",  # 1: bootloader is unlocked. 0: bootloader locked.
        "d": device,  # PRODUCT_DEVICE
        # "lockZoneChannel": "",  # Unknown
        "f": "1",  # Unknown, necessary
        "ov": version,  # ro.mi.os.version.incremental
        # "g": "00000000000000000000000000000000",  # Unknown, 32
        # "i": "0000000000000000000000000000000000000000000000000000000000000000",  # Unknown, 64
        # "i2": "0000000000000000000000000000000000000000000000000000000000000000",  # Unknown, 64
        # "isR": "0",  # ro.debuggable
        "l": "zh_CN"
        if "_global" not in device
        else "en_US",  # The locale. (for changelog)
        # "n": "ct",  # ro.carrier.name
        # "p": device,  # PRODUCT_DEVICE
        # "pb": "Xiaomi",  # "Redmi", PRODUCT_BRAND
        "r": "CN"
        if "_global" not in device
        else "GL",  # Sales regions. (for changelog)
        # MIUI version "MIUI-" + Build.VERSION.INCREMENTAL
        "v": f"miui-{version.replace('OS1', 'V816')}",
    }
    return json.dumps(data).replace(" ", "").replace("'", '"')


# AES 加密
def miui_encrypt(json_request, securityKey):
    cipher = AES.new(securityKey, AES.MODE_CBC, IV)
    padded_text = pad(json_request.encode("utf-8"), cipher.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.urlsafe_b64encode(encrypted_text).decode("utf-8")


# AES 解密
def miui_decrypt(encrypted_text, securityKey):
    cipher = AES.new(securityKey, AES.MODE_CBC, IV)
    encrypted_text_bytes = base64.urlsafe_b64decode(encrypted_text)
    decrypted_text = cipher.decrypt(encrypted_text_bytes)
    unpadded_text = unpad(decrypted_text, cipher.block_size).decode("utf-8")
    return json.loads(unpadded_text)


# 获取返回参数
def request(data):
    try:
        response = requests.post(url=MIUI_UPDATE_URL, data=data)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"向服务器发送请求时出错: {e}")
        return None


def parse_rom_branch(rom_branch):
    branch_descriptions = {
        "F": "F-正式版 (每月构建, 末尾数字不为 0 的为内部测试构建)",
        "X": "X-开发版 (每周构建)",
        "D": "D-开发版内测 (每日构建, 有时候会转到开发版)",
        "T": "T-绝密版 (曾经的内测版及未通过测试的版本)",
        "I": "I-内部构建 (内部测试使用, 有时候会转到开发版)",
    }
    return branch_descriptions.get(rom_branch, "其他版本")


# 分析返回参数
def choose(name, interface):
    interface_version = "v1" if interface == "1" else "v2"

    current_rom_info = name.get("CurrentRom", {})
    rom_device = current_rom_info.get("device", "Unknown")
    rom_version = current_rom_info.get("version", "Unknown")
    rom_codebase = current_rom_info.get("codebase", "Unknown")
    rom_md5 = current_rom_info.get("md5", "Unknown")
    rom_filename = current_rom_info.get("filename", "Unknown")
    rom_filesize = current_rom_info.get("filesize", "Unknown")
    rom_bigversion = (
        "HyperOS 1.0"
        if current_rom_info.get("bigversion") == "816"
        else "MIUI " + current_rom_info.get("bigversion", "Unknown")
    )
    rom_branch = parse_rom_branch(current_rom_info.get("branch", "Unknown"))
    rom_changelog = re.sub(
        r"\n\s*\n",
        "\n",
        json.dumps(
            current_rom_info.get("changelog", "Unknown"),
            indent=2,
            ensure_ascii=False,
            allow_nan=True,
        )
        .replace("[", "")
        .replace("]", "")
        .replace("{", "")
        .replace("}", "")
        .replace('"', "")
        .replace("txt:", "")
        .replace(",", ""),
    )

    latset_rom_info = name.get("LatestRom", {})
    latset_rom_md5 = latset_rom_info.get("md5", "Unknown")
    latset_rom_filename = latset_rom_info.get("filename", "Unknown")

    if rom_version == "Unknown":
        result = "\n\n未获取到相关 ROM 信息\n\n"
    elif rom_filename == "Unknown":
        result = f"\ndevice: {rom_device}\nversion: {rom_version}\ncodebase: Android {rom_codebase}\nbranch: {rom_branch}\ninterface: {interface_version}\n"
    elif rom_md5 == latset_rom_md5:
        result = f"\ndevice: {rom_device}\nversion: {rom_version}\nbigversion: {rom_bigversion}\ncodebase: Android {rom_codebase}\nbranch: {rom_branch}\ninterface: {interface_version}\n\nfilename: {rom_filename}\nfilesize: {rom_filesize}\ndownload: https://ultimateota.d.miui.com/{rom_version}/{latset_rom_filename}\nchangelog:\n{rom_changelog}\n"
    else:
        result = f"\ndevice: {rom_device}\nversion: {rom_version}\nbigversion: {rom_bigversion}\ncodebase: Android {rom_codebase}\nbranch: {rom_branch}\ninterface: {interface_version}\n\nfilename: {rom_filename}\nfilesize: {rom_filesize}\ndownload: https://bigota.d.miui.com/{rom_version}/{rom_filename}\nchangelog:\n{rom_changelog}\n"

    print(result)


# 小米登录管理器类 - 从 xiaomi_login.py 合并
class XiaomiLoginManager:
    def __init__(self):
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = requests.session()
        self._sign = None
        self._ssecurity = None
        self.userId = None
        self._cUserId = None
        self._passToken = None
        self._location = None
        self._code = None
        self._serviceToken = None
        
    @staticmethod
    def generate_agent():
        agent_id = "".join(
            map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)])
        )
        random_text = "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(18)]))
        return f"{random_text}-{agent_id} APP/com.xiaomi.mihome APPV/10.5.201"
    
    @staticmethod
    def generate_device_id():
        return "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(6)]))
    
    @staticmethod
    def to_json(response_text):
        return json.loads(response_text.replace("&&&START&&&", ""))
    
    def login_step_1(self, username):
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=miuiromota&_json=true"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        cookies = {
            "userId": username
        }
        response = self._session.get(url, headers=headers, cookies=cookies)
        json_resp = self.to_json(response.text)
        if response.status_code == 200:
            if "_sign" in json_resp:
                self._sign = json_resp["_sign"]
                return True
            elif "ssecurity" in json_resp:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp["userId"]
                self._cUserId = json_resp["cUserId"]
                self._passToken = json_resp["passToken"]
                self._location = json_resp["location"]
                self._code = json_resp["code"]
                return True
        return False
    
    def login_step_2(self, username, password):
        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        fields = {
            "sid": "miuiromota",
            "hash": hashlib.md5(str.encode(password)).hexdigest().upper(),
            "user": username,
            "_sign": self._sign,
            "_json": "true",
            "_locale": "zh_CN",
        }
        
        response = self._session.post(url, headers=headers, params=fields, allow_redirects=False)
        valid = response is not None and response.status_code == 200
        
        if valid:
            json_resp = self.to_json(response.text)
            if "captchaUrl" in json_resp and json_resp["captchaUrl"] is not None:
                captcha_code = self.handle_captcha(json_resp["captchaUrl"])
                if not captcha_code:
                    return False, "验证码输入失败"
                # Add captcha code to the fields and retry
                fields["captCode"] = captcha_code
                response = self._session.post(url, headers=headers, params=fields, allow_redirects=False)
                if response is not None and response.status_code == 200:
                    json_resp = self.to_json(response.text)
                else:
                    return False, "验证码重试失败"
                if "code" in json_resp and json_resp["code"] == 87001:
                    return False, "无效的验证码"
            
            description = json_resp.get("description", "")
            if description != "成功" and "ssecurity" not in json_resp:
                return False, description
            
            valid = "ssecurity" in json_resp and len(str(json_resp["ssecurity"])) > 4
            if valid:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp.get("userId", None)
                self._cUserId = json_resp.get("cUserId", None)
                self._passToken = json_resp.get("passToken", None)
                self._location = json_resp.get("location", None)
                self._code = json_resp.get("code", None)
            else:
                if "notificationUrl" in json_resp:
                    verify_url = json_resp["notificationUrl"]
                    
                    print(f"需要双因素认证，请使用以下URL获取2FA验证码：")
                    print(f"{verify_url}")
                    print(f"不要在小米网站上输入验证码！")
                    print()
                    print("请输入2FA验证码：")
                    ticket = input()
                    print()
                    
                    json_resp = self.verify_ticket(verify_url, ticket)
                    if not json_resp:
                        return False, "2FA验证失败"
                    
                    location = json_resp["location"]
                    self._session.get(location, allow_redirects=True)
                    self.login_step_1(username)
                    
                    return True, "成功"
                else:
                    return False, "登录失败"
        else:
            return False, "服务器响应错误"
        return valid, description if description else "成功"
    
    def verify_ticket(self, verify_url, ticket):
        path = 'identity/authStart'
        if path not in verify_url:
            return None
        resp = self._session.get(verify_url.replace(path, 'identity/list'))
        identity_session = resp.cookies.get('identity_session')
        if not identity_session:
            return False
        data = self.to_json(resp.text) or {}
        flag = data.get('flag', 4)
        options = data.get('options', [flag])
        
        for flag in options:
            api = {
                4: '/identity/auth/verifyPhone',
                8: '/identity/auth/verifyEmail',
            }.get(flag)
            if not api:
                continue
            resp = self._session.post(
                'https://account.xiaomi.com' + api,
                params={
                    '_dc': int(time.time() * 1000),
                },
                data={
                    '_flag': flag,
                    'ticket': ticket,
                    'trust': 'true',
                    '_json': 'true',
                },
                cookies={
                    'identity_session': identity_session,
                },
            )
            data = self.to_json(resp.text)
            if data.get('code') == 0:
                return data
        
        return False
    
    def login_step_3(self):
        # 处理登录结果，生成clientSign并获取cookie
        if not self._location:
            return False, "未获取到cookie请求地址"
        
        # 生成clientSign
        sha1 = hashlib.sha1()
        sha1.update(("nonce=" + str(self._code) + "&" + self._ssecurity).encode("utf-8"))
        client_sign = base64.encodebytes(bytearray.fromhex(sha1.hexdigest()))
        client_sign = client_sign.decode("utf-8").strip()
        
        # 获取cookie
        nurl = self._location + "&_userIdNeedEncrypt=true&clientSign=" + client_sign
        response3 = self._session.get(url=nurl, timeout=30)
        cookies_dict = requests.utils.dict_from_cookiejar(response3.cookies)
        
        if "serviceToken" not in cookies_dict:
            return False, "登录失败，未获取到serviceToken"
        
        self._serviceToken = cookies_dict["serviceToken"]
        return True, "成功"
    
    def handle_captcha(self, captcha_url):
        # Full URL in case it's relative
        if captcha_url.startswith("/"):
            captcha_url = "https://account.xiaomi.com" + captcha_url
        
        response = self._session.get(captcha_url, stream=False)
        if response.status_code != 200:
            return ""
        
        print(f"需要验证码验证。")
        try:
            # 尝试使用colorama
            try:
                from colorama import Fore, Style
                print(f"验证码图片URL: {Fore.BLUE}http://127.0.0.1:31415{Style.RESET_ALL}")
            except:
                print(f"验证码图片URL: http://127.0.0.1:31415")
            
            # Try to serve an image file
            start_image_server(response.content)
        except Exception as e1:
            # Save image to a temporary file
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
                    tmp.write(response.content)
                    tmp_path = tmp.name
                print(f"验证码图片已保存至: {tmp_path}")
                try:
                    img = Image.open(tmp_path)
                    img.show()
                except Exception as e2:
                    print(f"请打开 {tmp_path} 并解决验证码。")
            except:
                print("无法保存验证码图片，请手动处理。")
        
        # Ask user for a captcha solution
        try:
            from colorama import Fore, Style
            print(f"请输入图片中显示的验证码 {Fore.BLUE}(区分大小写){Style.RESET_ALL}:")
        except:
            print(f"请输入图片中显示的验证码 (区分大小写):")
        captcha_solution = input().strip()
        print()
        return captcha_solution
    
    def login(self, username, password):
        try:
            from colorama import init
            init(autoreset=True)
        except:
            pass
        
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="mi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="xiaomi.com")
        
        try:
            from colorama import Fore
            print(f"{username}：登录中...")
        except:
            print(f"{username}：登录中...")
        
        if not self.login_step_1(username):
            return False, "用户名无效"
        
        success, message = self.login_step_2(username, password)
        if not success:
            return False, message
        
        success, message = self.login_step_3()
        if not success:
            return False, message
        
        # 返回登录信息
        login_info = {
            "userId": self.userId,
            "ssecurity": self._ssecurity,
            "serviceToken": self._serviceToken
        }
        return True, login_info

# 辅助函数：启动验证码图片服务器
def start_image_server(image: bytes) -> None:
    class ImgHttpHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(image)

        def log_message(self, msg, *args) -> None:
            pass

    httpd = HTTPServer(("", 31415), ImgHttpHandler)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

# 登录函数 - 使用合并的 XiaomiLoginManager 类
def login():
    account = input("账号：")
    password = getpass.getpass("密码：")
    
    if not account or not password:
        print("账号或密码不能为空")
        return
    
    try:
        manager = XiaomiLoginManager()
        success, result = manager.login(account, password)
        
        if success:
            # 使用miui_updater.py的cookies处理函数
            save_cookies_to_file(result)
            print(f"{account}: 登录成功")
        else:
            print(f"{account}: {result}")
    except Exception as e:
        print(f"登录出错: {e}")
    
    sys.exit()


## 输出 ROM 信息
def rom_info(codename, rom_version, android_version, verbose):
    userId, securityKey, serviceToken = read_cookies_from_file()
    interface = "1" if serviceToken == "" else "2"
    securityKey = b"miuiotavalided11" if serviceToken == "" else securityKey
    json_data = generate_json(codename, rom_version, android_version, userId)
    encrypted_text = miui_encrypt(json_data, securityKey)
    post_data = {"q": encrypted_text, "t": serviceToken, "s": interface}
    requested_encrypted_text = request(post_data)
    requested_decrypted_text = miui_decrypt(requested_encrypted_text, securityKey)
    if verbose:
        print(requested_decrypted_text)
    else:
        choose(requested_decrypted_text, interface)


# 保存 cookies - miui_updater.py 原有的函数
def save_cookies_to_file(cookies_dict, filename="cookies.json"):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(cookies_dict, file, ensure_ascii=False, indent=4)


# 读取 cookies - miui_updater.py 原有的函数，增加异常处理
def read_cookies_from_file(filename="cookies.json"):
    if os.path.isfile(filename):
        try:
            with open(filename, "r", encoding="utf-8") as file:
                # 检查文件是否为空
                content = file.read().strip()
                if not content:
                    return "", "", ""
                
                file.seek(0)  # 重置文件指针到开头
                cookies = json.load(file)
                userId = cookies.get("userId", "")
                securityKey = base64.b64decode(cookies.get("ssecurity", "")) if cookies.get("ssecurity") else ""
                serviceToken = cookies.get("serviceToken", "")
                return userId, securityKey, serviceToken
        except (json.JSONDecodeError, KeyError, base64.binascii.Error, Exception):
            # 处理JSON解析错误、键不存在、base64解码错误等所有异常
            return "", "", ""
    return "", "", ""


# 使用提示
def parse_arguments():
    parser = argparse.ArgumentParser(description="Xiaomi Update Info")
    parser.add_argument("codename", help="Device codename", nargs="?")
    parser.add_argument("rom_version", help="ROM version", nargs="?")
    parser.add_argument("android_version", help="Android version", nargs="?")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="verbose output the returned json"
    )
    parser.add_argument(
        "-l", "--login", action="store_true", help="login to get using v2 interface"
    )

    return parser.parse_args()


# 主程序
def main():
    args = parse_arguments()
    if args.login:
        login()
    elif args.codename and args.rom_version and args.android_version:
        rom_info(args.codename, args.rom_version, args.android_version, args.verbose)  # 修复这里的rom_version变量名
    else:
        print("请输入正确的参数，使用 -h 查看帮助")
        sys.exit()


if __name__ == "__main__":
    main()
