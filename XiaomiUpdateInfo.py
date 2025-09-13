#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import random
import re
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from PIL import Image
except ModuleNotFoundError:
    Image = None

try:
    from colorama import Fore, Style, init
except ModuleNotFoundError:
    Fore = Style = init = None


# ============================= 配置类 =============================

class Config:
    # API 地址
    MIUI_UPDATE_URL = "https://update.miui.com/updates/miotaV3.php"
    LOGIN_URL = "https://account.xiaomi.com/pass/serviceLoginAuth2"
    DOWNLOAD_BASE_URL_ULTIMATE = "https://ultimateota.d.miui.com"
    DOWNLOAD_BASE_URL_BIG = "https://bigota.d.miui.com"
    
    # 加密相关
    IV = b"0102030405060708"
    DEFAULT_SECURITY_KEY = b"miuiotavalided11"
    
    # 网络配置
    DEFAULT_TIMEOUT = 30
    CAPTCHA_SERVER_PORT = 31415
    
    # 文件配置
    DEFAULT_COOKIES_FILE = "cookies.json"
    
    # 本地化配置
    LOCALE_MAP = {
        'global': 'en_US',
        'cn': 'zh_CN'
    }
    
    REGION_MAP = {
        'global': 'GL',
        'cn': 'CN'
    }


# ============================= 数据类 =============================

@dataclass
class RomInfo:
    device: str = "Unknown"
    version: str = "Unknown"
    codebase: str = "Unknown"
    md5: str = "Unknown"
    filename: str = "Unknown"
    filesize: str = "Unknown"
    bigversion: str = "Unknown"
    osbigversion: Optional[str] = None
    isBeta: Optional[str] = None
    isGov: Optional[str] = None
    branch: str = "Unknown"
    changelog: Any = "Unknown"

    @property
    def display_bigversion(self) -> Optional[str]:
        if self.bigversion == "816":
            return "HyperOS 1.0"
        if self.bigversion == "0":
            return None
        if self.bigversion and self.bigversion != "Unknown":
            return f"MIUI {self.bigversion}"
        return None

    @property
    def is_global_rom(self) -> bool:
        return "_global" in self.device

@dataclass
class ApiRomResponse:
    current: RomInfo
    latest: RomInfo

@dataclass
class LoginCredentials:
    userId: str
    ssecurity: str
    serviceToken: str
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "userId": self.userId,
            "ssecurity": self.ssecurity,
            "serviceToken": self.serviceToken
        }


# ============================= 异常类 =============================

class XiaomiUpdateException(Exception):
    """基础异常类"""
    pass


class LoginException(XiaomiUpdateException):
    """登录相关异常"""
    pass


class CryptographyException(XiaomiUpdateException):
    """加密解密相关异常"""
    pass


class ApiException(XiaomiUpdateException):
    """API 请求相关异常"""
    pass


# ============================= 工具类 =============================

class CryptoManager:
    
    @staticmethod
    def encrypt(plaintext: str, security_key: bytes) -> str:
        try:
            cipher = AES.new(security_key, AES.MODE_CBC, Config.IV)
            padded_text = pad(plaintext.encode("utf-8"), cipher.block_size)
            encrypted_text = cipher.encrypt(padded_text)
            return base64.urlsafe_b64encode(encrypted_text).decode("utf-8")
        except Exception as e:
            raise CryptographyException(f"加密失败: {e}") from e
    
    @staticmethod
    def decrypt(encrypted_text: str, security_key: bytes) -> Dict[str, Any]:
        try:
            cipher = AES.new(security_key, AES.MODE_CBC, Config.IV)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text)
            decrypted_text = cipher.decrypt(encrypted_bytes)
            unpadded_text = unpad(decrypted_text, cipher.block_size).decode("utf-8")
            return json.loads(unpadded_text)
        except Exception as e:
            raise CryptographyException(f"解密失败: {e}") from e


# ============================= 请求数据构建类 =============================

class RequestDataBuilder:

    @staticmethod
    def build_rom_request_data(device: str, version: str, android: str, user_id: Optional[str]) -> str:
        is_global = "_global" in device
        
        data = {
            "id": user_id,
            "c": android,  # Android 版本
            "d": device,   # 设备代号
            "f": "1",      # 必需字段
            "ov": version, # ROM 版本
            "l": Config.LOCALE_MAP['global' if is_global else 'cn'],  # 语言
            "r": Config.REGION_MAP['global' if is_global else 'cn'],  # 区域
            "v": f"miui-{version.replace('OS1', 'V816')}",  # ROM 版本
        }
        
        return json.dumps(data, separators=(",", ":"))


# ============================= 文件管理类 =============================

class FileManager:
    
    @staticmethod
    def save_login_credentials(credentials: LoginCredentials, filename: str = Config.DEFAULT_COOKIES_FILE) -> None:
        try:
            with open(filename, "w", encoding="utf-8") as file:
                json.dump(credentials.to_dict(), file, ensure_ascii=False, indent=4)
        except Exception as e:
            raise IOError(f"保存凭据失败: {e}") from e
    
    @staticmethod
    def load_login_credentials(filename: str = Config.DEFAULT_COOKIES_FILE) -> Tuple[str, bytes, str]:
        if not os.path.isfile(filename):
            return "", b"", ""
            
        try:
            with open(filename, "r", encoding="utf-8") as file:
                content = file.read().strip()
                if not content:
                    return "", b"", ""
                
                file.seek(0)
                credentials = json.load(file)
                
                user_id = credentials.get("userId", "")
                ssecurity = credentials.get("ssecurity", "")
                service_token = credentials.get("serviceToken", "")
                
                security_key = base64.b64decode(ssecurity) if ssecurity else b""
                
                return user_id, security_key, service_token
                
        except Exception:
            return "", b"", ""


# ============================= 验证码处理类 =============================

class CaptchaHandler:

    def __init__(self):
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
    
    def start_image_server(self, image_data: bytes) -> None:
        class ImageHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.end_headers()
                self.wfile.write(image_data)
            
            def log_message(self, format, *args):
                pass  # 禁用日志输出
        
        try:
            self._server = HTTPServer(("", Config.CAPTCHA_SERVER_PORT), ImageHandler)
            self._thread = threading.Thread(target=self._server.serve_forever)
            self._thread.daemon = True
            self._thread.start()
        except Exception as e:
            print(f"启动验证码服务器失败: {e}")
    
    def handle_captcha_display(self, image_data: bytes) -> str:
        print("需要验证码验证")
        try:
            # 尝试启动本地服务器显示验证码
            self.start_image_server(image_data)
            self._display_captcha_url()
        except Exception:
            # 备用方案，保存到临时文件
            self._save_captcha_to_temp_file(image_data)
        
        return self._get_captcha_input()
    
    def _display_captcha_url(self) -> None:
        url = f"http://127.0.0.1:{Config.CAPTCHA_SERVER_PORT}"
        if Fore and Style:
            print(f"验证码图片 URL: {Fore.BLUE}{url}{Style.RESET_ALL}")
        else:
            print(f"验证码图片 URL: {url}")
    
    def _save_captcha_to_temp_file(self, image_data: bytes) -> None:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
                tmp.write(image_data)
                tmp_path = tmp.name
            
            print(f"验证码图片已保存至: {tmp_path}")
            
            # 尝试使用 PIL 显示图片
            if Image:
                try:
                    img = Image.open(tmp_path)
                    img.show()
                except Exception:
                    print(f"请手动打开 {tmp_path} 查看验证码")
            else:
                print(f"请手动打开 {tmp_path} 查看验证码")
                
        except Exception as e:
            print(f"保存验证码图片失败: {e}")
    
    def _get_captcha_input(self) -> str:
        if Fore and Style:
            print(f"请输入图片中显示的验证码 {Fore.BLUE}(不区分大小写){Style.RESET_ALL}: ")
        else:
            print("请输入图片中显示的验证码 (不区分大小写): ")
        
        return input().strip()


# ============================= 核心业务类 =============================

class XiaomiLoginManager:

    def __init__(self):
        self._session = requests.Session()
        self._captcha_handler = CaptchaHandler()
        self._user_agent = self._generate_user_agent()
        self._credentials: Optional[LoginCredentials] = None
        self._location: Optional[str] = None
        
        # 初始化 colorama
        if init:
            init(autoreset=True)
    
    @staticmethod
    def _generate_user_agent() -> str:
        agent_id = "".join(chr(random.randint(65, 69)) for _ in range(13))
        random_text = "".join(chr(random.randint(97, 122)) for _ in range(18))
        return f"{random_text}-{agent_id} APP/com.android.updater APPV/9.1.0"
    
    @staticmethod
    def _parse_json_response(response_text: str) -> Dict[str, Any]:
        return json.loads(response_text.replace("&&&START&&&", ""))
    
    def login(self, username: str, password: str) -> LoginCredentials:
        print(f"\n{username}: 登录中...\n")
        
        # 第一步: 账号密码验证
        temp_credentials = self._login_step1(username, password)
        
        # 第二步: 获取服务令牌
        service_token = self._login_step2(temp_credentials)
        
        # 构建完整凭据
        self._credentials = LoginCredentials(
            userId=temp_credentials.userId,
            ssecurity=temp_credentials.ssecurity,
            serviceToken=service_token
        )
        
        return self._credentials
    
    def _login_step1(self, username: str, password: str) -> LoginCredentials:
        url = Config.LOGIN_URL
        headers = {
            "User-Agent": self._user_agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # 构建请求参数
        fields = {
            "sid": "miuiromota",
            "hash": hashlib.md5(password.encode()).hexdigest().upper(),
            "user": username,
            "_json": "true",
            "_locale": "zh_CN",
        }
        
        # 发送登录请求
        response = self._session.post(
            url, headers=headers, params=fields, 
            allow_redirects=False, timeout=Config.DEFAULT_TIMEOUT
        )
        
        if not response or response.status_code != 200:
            raise LoginException("服务器响应错误")
        
        try:
            json_resp = self._parse_json_response(response.text)
        except Exception as e:
            raise LoginException("服务器返回格式异常") from e
        
        # 处理验证码
        if "captchaUrl" in json_resp and json_resp["captchaUrl"]:
            json_resp = self._handle_captcha_challenge(json_resp["captchaUrl"], fields, headers, url)
        
        # 处理二次认证
        if "notificationUrl" in json_resp:
            self._handle_2fa_challenge(json_resp["notificationUrl"])
            return self._login_step1(username, password)
        
        # 验证登录结果
        if json_resp.get("description") != "成功" or "ssecurity" not in json_resp:
            error_msg = json_resp.get("description", "登录失败")
            raise LoginException(error_msg)
        
        if len(str(json_resp.get("ssecurity", ""))) <= 4:
            raise LoginException("获取安全令牌失败")
        
        # 保存 location 地址用于第二步
        self._location = json_resp.get("location")
        
        return LoginCredentials(
            userId=json_resp.get("userId", ""),
            ssecurity=json_resp.get("ssecurity", ""),
            serviceToken=""
        )
    
    def _handle_captcha_challenge(self, captcha_url: str, fields: Dict, headers: Dict, url: str) -> Dict[str, Any]:
        # 获取验证码图片
        if captcha_url.startswith("/"):
            captcha_url = "https://account.xiaomi.com" + captcha_url
        
        captcha_response = self._session.get(captcha_url, timeout=Config.DEFAULT_TIMEOUT)
        if captcha_response.status_code != 200:
            raise LoginException("获取验证码失败")
        
        # 显示验证码并获取用户输入
        captcha_code = self._captcha_handler.handle_captcha_display(captcha_response.content)
        if not captcha_code:
            raise LoginException("验证码输入失败")
        
        # 重新提交带验证码的请求
        fields["captCode"] = captcha_code
        retry_response = self._session.post(
            url, headers=headers, params=fields,
            allow_redirects=False, timeout=Config.DEFAULT_TIMEOUT
        )
        
        if not retry_response or retry_response.status_code != 200:
            raise LoginException("验证码重试失败")
        
        try:
            json_resp = self._parse_json_response(retry_response.text)
        except Exception as e:
            raise LoginException("验证码响应格式异常") from e
        
        if json_resp.get("code") == 87001:
            raise LoginException("无效的验证码")
        
        return json_resp
    
    def _handle_2fa_challenge(self, notification_url: str) -> None:
        print("需要二次认证，请使用以下 URL 获取 2FA 验证码: ")
        print(notification_url)
        print("\n不要在小米网站上输入验证码!!!")
        print()
        
        ticket = input("请输入 2FA 验证码: ").strip()
        if not ticket:
            raise LoginException("2FA 验证码不能为空")
        
        if not self._verify_2fa_ticket(notification_url, ticket):
            raise LoginException("2FA 验证失败")
    
    def _verify_2fa_ticket(self, verify_url: str, ticket: str) -> bool:
        path = 'identity/authStart'
        if path not in verify_url:
            return False
        
        # 获取身份会话
        list_url = verify_url.replace(path, 'identity/list')
        resp = self._session.get(list_url, timeout=Config.DEFAULT_TIMEOUT)
        identity_session = resp.cookies.get('identity_session')
        
        if not identity_session:
            return False
        
        try:
            data = self._parse_json_response(resp.text) or {}
        except Exception:
            return False
        
        flag = data.get('flag', 4)
        options = data.get('options', [flag])
        
        # 尝试不同的验证方式
        for flag in options:
            api = {
                4: '/identity/auth/verifyPhone',
                8: '/identity/auth/verifyEmail',
            }.get(flag)
            
            if not api:
                continue
            
            verify_resp = self._session.post(
                'https://account.xiaomi.com' + api,
                params={'_dc': int(time.time() * 1000)},
                data={
                    '_flag': flag,
                    'ticket': ticket,
                    'trust': 'true',
                    '_json': 'true',
                },
                cookies={'identity_session': identity_session},
                timeout=Config.DEFAULT_TIMEOUT,
            )
            
            try:
                verify_data = self._parse_json_response(verify_resp.text)
                if verify_data.get('code') == 0:
                    location = verify_data.get('location')
                    if location:
                        self._session.get(location, allow_redirects=True, timeout=Config.DEFAULT_TIMEOUT)
                    return True
            except Exception:
                continue
        
        return False
    
    def _login_step2(self, temp_credentials: LoginCredentials) -> str:
        if not self._location:
            # 如果没有获取到 location 地址，使用 v1 接口
            return ""
        
        try:
            # 构建完整的 URL
            full_url = self._location + "&_userIdNeedEncrypt=true"
            
            # 发送请求获取 cookie
            response = self._session.get(full_url, timeout=Config.DEFAULT_TIMEOUT)
            response.raise_for_status()
            
            # 从 cookies 中提取 serviceToken
            cookies_dict = requests.utils.dict_from_cookiejar(response.cookies)
            service_token = cookies_dict.get("serviceToken", "")
            
            if not service_token:
                # 如果无法获取 serviceToken，使用 v1 接口
                return ""
            
            return service_token
            
        except Exception:
            # 出现任何其他错误都返回空字符串，使用 v1 接口
            return ""


# ============================= ROM 信息查询类 =============================

class RomInfoManager:
    
    def __init__(self):
        self._crypto_manager = CryptoManager()
        self._request_builder = RequestDataBuilder()
    
    def query_rom_info(self, device: str, version: str, android: str, 
                      credentials: Optional[LoginCredentials] = None, verbose: bool = False) -> None:
        try:
            # 获取认证信息
            user_id, security_key, service_token = self._get_auth_info(credentials)
            
            # 确定接口版本
            interface_version = "2" if service_token else "1"
            
            # 构建请求数据
            json_data = self._request_builder.build_rom_request_data(device, version, android, user_id)
            
            # 加密请求数据
            encrypted_data = self._crypto_manager.encrypt(json_data, security_key)
            
            # 发送请求
            response_data = self._send_request(encrypted_data, service_token, interface_version)
            
            # 解密响应
            decrypted_data = self._crypto_manager.decrypt(response_data, security_key)
            
            # 输出结果
            if verbose:
                print(json.dumps(decrypted_data, indent=2, ensure_ascii=False))
            else:
                self._format_and_display_rom_info(decrypted_data, interface_version)
                
        except Exception as e:
            print(f"查询 ROM 信息失败: {e}")
    
    def _get_auth_info(self, credentials: Optional[LoginCredentials]) -> Tuple[str, bytes, str]:
        if credentials:
            user_id = credentials.userId
            security_key = base64.b64decode(credentials.ssecurity) if credentials.ssecurity else Config.DEFAULT_SECURITY_KEY
            service_token = credentials.serviceToken
        else:
            user_id, security_key, service_token = FileManager.load_login_credentials()
            if not security_key:
                security_key = Config.DEFAULT_SECURITY_KEY
        
        return user_id, security_key, service_token
    
    def _send_request(self, encrypted_data: str, service_token: str, interface_version: str) -> str:
        post_data = {
            "q": encrypted_data,
            "t": service_token,
            "s": interface_version
        }
        
        try:
            response = requests.post(
                Config.MIUI_UPDATE_URL, 
                data=post_data, 
                timeout=Config.DEFAULT_TIMEOUT
            )
            response.raise_for_status()
            
            if not response.text:
                raise ApiException("服务器返回空响应")
            
            return response.text
            
        except requests.RequestException as e:
            raise ApiException(f"请求失败: {e}") from e
    
    def _format_and_display_rom_info(self, data: Dict[str, Any], interface_version: str) -> None:
        formatter = RomInfoFormatter()
        formatter.display_rom_info(data, interface_version)


# ============================= 格式化输出类 =============================

class RomInfoFormatter:
    
    def display_rom_info(self, data: Dict[str, Any], interface_version: str) -> None:
        try:
            response = self._parse_api_response(data)
            formatted_output = self._format_rom_info(response, interface_version)
            print(formatted_output)
        except Exception as e:
            print(f"格式化 ROM 信息失败: {e}")
    
    def _parse_api_response(self, data: Dict[str, Any]) -> ApiRomResponse:
        return ApiRomResponse(
            current=self._parse_rom_info(data.get("CurrentRom", {})),
            latest=self._parse_rom_info(data.get("LatestRom", {}))
        )
    
    def _parse_rom_info(self, data: Dict[str, Any]) -> RomInfo:
        return RomInfo(
            device=data.get("device", "Unknown"),
            version=data.get("version", "Unknown"),
            codebase=data.get("codebase", "Unknown"),
            md5=data.get("md5", "Unknown"),
            filename=data.get("filename", "Unknown"),
            filesize=data.get("filesize", "Unknown"),
            bigversion=data.get("bigversion", "Unknown"),
            osbigversion=data.get("osbigversion"),
            isBeta=data.get("isBeta"),
            isGov=data.get("isGov"),
            branch=data.get("branch", "Unknown"),
            changelog=data.get("changelog", "Unknown"),
        )
    
    def _format_rom_info(self, response: ApiRomResponse, interface_version: str) -> str:
        current = response.current
        latest = response.latest
        
        if current.version == "Unknown":
            return "\n\n未获取到相关 ROM 信息\n\n"
        
        # 构建基本信息
        result_lines = [
            f"interface: v{interface_version}",
            f"device: {current.device}",
            f"version: {current.version}",
        ]
        
        # 添加大版本信息
        if current.display_bigversion:
            result_lines.append(f"bigversion: {current.display_bigversion}")
        
        # 添加OS大版本信息
        if current.osbigversion and current.osbigversion != "0":
            result_lines.append(f"osbigversion: {current.osbigversion}")
        
        # 添加基础信息
        result_lines.extend([
            f"codebase: Android {current.codebase}",
            f"branch: {current.branch}",
        ])
        
        # 添加特殊标记
        if current.isBeta and current.isBeta != "0":
            result_lines.append(f"isBeta: {current.isBeta}")
        
        if current.isGov and current.isGov != "0":
            result_lines.append(f"isGov: {current.isGov}")
        
        # 如果没有文件名，只显示基本信息
        if current.filename == "Unknown":
            return "\n" + "\n".join(result_lines) + "\n"
        
        # 添加文件信息
        result_lines.extend([
            f"filename: {current.filename}",
            f"filesize: {current.filesize}",
        ])
        
        # 添加下载链接
        if current.md5 == latest.md5:
            download_url = f"{Config.DOWNLOAD_BASE_URL_ULTIMATE}/{current.version}/{latest.filename}"
        else:
            download_url = f"{Config.DOWNLOAD_BASE_URL_BIG}/{current.version}/{current.filename}"
        
        result_lines.append(f"download: {download_url}")
        
        # 添加更新日志
        changelog = self._format_changelog(current.changelog)
        result_lines.append(f"changelog:{changelog}")
        
        return "\n" + "\n".join(result_lines)
    
    def _format_changelog(self, raw_changelog: Any) -> str:
        try:
            if isinstance(raw_changelog, (dict, list)):
                text = json.dumps(raw_changelog, indent=2, ensure_ascii=False, allow_nan=True)
            else:
                text = str(raw_changelog)

            text = (
                text.replace("[", "").replace("]", "")
                .replace("{", "").replace("}", "")
                .replace('"', "").replace("txt:", "")
                .replace(",", "")
            )

            text = re.sub(r"\n\s*\n", "\n", text)
            
            return text
            
        except Exception:
            return str(raw_changelog)


# ============================= 应用程序类 =============================

class XiaomiUpdateApp:

    def __init__(self):
        self.login_manager = XiaomiLoginManager()
        self.rom_manager = RomInfoManager()
        self.file_manager = FileManager()
    
    def run(self) -> None:
        try:
            args = self._parse_arguments()
            
            if args.login:
                self._handle_login()
            elif args.codename and args.rom_version and args.android_version:
                self._handle_rom_query(args)
            else:
                print("请输入正确的参数，使用 -h 查看帮助")
                sys.exit(1)
                
        except KeyboardInterrupt:
            print("\n\n操作已取消")
            sys.exit(1)
        except Exception as e:
            print(f"应用程序错误: {e}")
            sys.exit(1)
    
    def _parse_arguments(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="XiaomiUpdateInfo",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
usage examples:
  %(prog)s dada OS2.0.215.0.VOCCNXM 15                    # Check CN ROM information
  %(prog)s dada_global OS2.0.222.0.WOCMIXM 16             # Check Global ROM Information
  %(prog)s dada OS2.0.215.0.VOCCNXM 15 -v                 # Display detailed JSON response info
            """
        )
        parser.add_argument(
            "codename", 
            help="Device code (e.g. dada, dada_global)", 
            nargs="?"
        )
        parser.add_argument(
            "rom_version", 
            help="ROM version (e.g. OS2.0.215.0.VOCCNXM)", 
            nargs="?"
        )
        parser.add_argument(
            "android_version", 
            help="Android version (e.g. 15, 16)", 
            nargs="?"
        )
        parser.add_argument(
            "-v", "--verbose", 
            action="store_true", 
            help="Display detailed Json response info"
        )
        parser.add_argument(
            "-l", "--login", 
            action="store_true", 
            help="Login Xiaomi account to use v2 API."
        )
        return parser.parse_args()
    
    def _handle_login(self) -> None:
        try:
            username = input("Account: ").strip()
            password = getpass.getpass("Password: ")
            
            if not username or not password:
                raise LoginException("账号或密码不能为空")
            
            credentials = self.login_manager.login(username, password)
            self.file_manager.save_login_credentials(credentials)
            
            print(f"\n{username}: 登录成功")
            
        except LoginException as e:
            print(f"登录失败: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"登录过程中出现错误: {e}")
            sys.exit(1)
    
    def _handle_rom_query(self, args: argparse.Namespace) -> None:
        try:
            self.rom_manager.query_rom_info(
                device=args.codename,
                version=args.rom_version,
                android=args.android_version,
                verbose=args.verbose
            )
        except Exception as e:
            print(f"查询 ROM 信息失败: {e}")
            sys.exit(1)


# ============================= 程序入口 =============================

def main() -> None:
    app = XiaomiUpdateApp()
    app.run()

if __name__ == "__main__":
    main()