#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pip install pycryptodome
# pip install requests

import base64, json, re

from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from requests import post


miui_key = b"miuiotavalided11"
miui_iv = b"0102030405060708"
check_url = "https://update.miui.com/updates/miotaV3.php"


def generate_json(device, version, android):
    data = {  # After testing, the commented out parts do not need to be assigned values.
        # "obv": "OS1.0", # ro.mi.os.version.name
        # "channel":"",  # Unknown
        # "sys": "0",  # Unknown
        # "bv": "816",  # bigversion
        # "id": "",  # id
        # "sn": "0x0000000000000000",  # SN
        # "a": "0",  # Unknown
        # "b": "F",  # MIUI branch - miui.os.Build.IS_STABLE_VERSION ? "F" : (miui.os.Build.IS_XIAOMI || !t(context)) ? "X" : "S";
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
        "l": "zh_cn",  # The locale. (for changelog)
        # "n": "ct",  # ro.carrier.name
        # "p": device,  # PRODUCT_DEVICE
        # "pb": "Xiaomi", "Redmi",  # PRODUCT_BRAND
        "r": "CN",  # Sales regions. (for changelog)
        # MIUI version "MIUI-" + Build.VERSION.INCREMENTAL
        "v": f"miui-{version.replace('OS1', 'V816')}",
        # "sdk": "34" if android == "14" else "33",   # Android SDK
        # "pn": device,  # PRODUCT_NAME
        # "options": {
        # "zone": "1" if "_global" not in device else "2",  # ro.rom.zone
        # "hashId":"0000000000000000",
        # "ab": "1", # Whether to support A/B update
        # "previewPlan": "0",
        # "sv": 3,
        # "av": "8.4.0", # com.android.update application version
        # "cv": version.replace('OS1', 'V816')
        # }
    }
    return json.dumps(data).replace(" ", "")


def miui_encrypt(json_request):
    cipher = AES.new(miui_key, AES.MODE_CBC, miui_iv)
    decrypted_text = pad(bytes(json_request, "utf-8"), cipher.block_size)
    encrypted_text = cipher.encrypt(decrypted_text)
    return base64.b64encode(encrypted_text)


def miui_decrypt(encrypted_text):
    cipher = AES.new(miui_key, AES.MODE_CBC, miui_iv)
    encrypted_text = base64.b64decode(encrypted_text)
    decrypted_text = cipher.decrypt(encrypted_text)
    return json.loads(unpad(decrypted_text, cipher.block_size).decode("utf-8").strip())


def request(data):
    response = post(check_url, data=data)
    return response.text


def choose(name):
    current_rom_info = name.get("CurrentRom", {})
    rom_device = current_rom_info.get("device", "Unknown")
    rom_name = current_rom_info.get("name", "Unknown")
    rom_bigversion = current_rom_info.get("bigversion", "Unknown")
    rom_codebase = current_rom_info.get("codebase", "Unknown")
    rom_branch = current_rom_info.get("branch", "Unknown")
    rom_md5 = current_rom_info.get("md5", "Unknown")
    rom_filename = current_rom_info.get("filename", "Unknown")
    rom_filesize = current_rom_info.get("filesize", "Unknown")
    rom_changelog = current_rom_info.get("changelog", "Unknown")

    rom_icon = name.get("Icon", "Unknown")

    latset_rom_info = name.get("LatestRom", {})
    latset_rom_md5 = latset_rom_info.get("md5", "Unknown")
    latset_rom_filename = latset_rom_info.get("filename", "Unknown")

    if rom_branch == "F":
        rom_branch_log = "正式版"
    elif rom_branch == "X":
        rom_branch_log = "开发版公测"
    elif rom_branch == "D":
        rom_branch_log = "开发版内测"
    elif rom_branch == "T":
        rom_branch_log = "绝密版"
    elif rom_branch == "I":
        rom_branch_log = "待发布"
    else:
        rom_branch_log = "未知"

    if (rom_branch == "F" or rom_branch == "X") and rom_bigversion == "816":
        rom_name = "OS" + rom_name

    if rom_bigversion == "816":
        rom_bigversion = "HyperOS 1.0"

    rom_icon = re.sub(
        r"\n\s*\n",
        "\n",
        json.dumps(rom_icon, indent=0, ensure_ascii=False, allow_nan=True)
        .replace("[", "")
        .replace("]", "")
        .replace("{", "")
        .replace("}", "")
        .replace('"', "")
        .replace("txt:", ""),
    )

    rom_changelog = re.sub(
        r"\n\s*\n",
        "\n",
        json.dumps(rom_changelog, indent=2, ensure_ascii=False, allow_nan=True)
        .replace("[", "")
        .replace("]", "")
        .replace("{", "")
        .replace("}", "")
        .replace('"', "")
        .replace("txt:", ""),
    )

    if rom_name == "Unknown":
        result = "\n\n未获取到相关 ROM 信息\n\n"
    elif rom_filename == "Unknown":
        result = f"\ndevice: {rom_device}\nname: {rom_name}\ncodebase: Android {rom_codebase}\nbranch: {rom_branch_log}\nicon:\n{rom_icon}\n"
    elif rom_md5 == latset_rom_md5:
        result = f"\ndevice: {rom_device}\nname: {rom_name}\nbigversion: {rom_bigversion}\ncodebase: Android {rom_codebase}\nbranch: {rom_branch_log}\n\nfilename: {rom_filename}\nfilesize: {rom_filesize}\ndownload: https://ultimateota.d.miui.com/{rom_name}/{latset_rom_filename}\nchangelog:\n{rom_changelog}\n"
    else:
        result = f"\ndevice: {rom_device}\nname: {rom_name}\nbigversion: {rom_bigversion}\ncodebase: Android {rom_codebase}\nbranch: {rom_branch_log}\n\nfilename: {rom_filename}\nfilesize: {rom_filesize}\ndownload: https://bigota.d.miui.com/{rom_name}/{rom_filename}\nchangelog:\n{rom_changelog}\n"

    print(result)


def usage():
    print(
        "\nUsage: XiaomiUpdateInfo.py codename rom_version android_version\n\nExample: \n(1) XiaomiUpdateInfo.py houji OS1.0.20.0.UNCCNXM 14\n(2) XiaomiUpdateInfo.py fuxi V14.0.5.0.UMCCNXM 14\n"
    )
    exit()


def main():
    if len(argv) < 4:
        usage()
    device = argv[1]
    version = argv[2]
    android = argv[3]
    json_data = generate_json(device, version, android)
    encrypted = miui_encrypt(json_data)
    post_data = {"q": encrypted, "t": "", "s": "1"}
    encrypted_text = request(post_data)
    decrypted_text = miui_decrypt(encrypted_text)

    if len(argv) == 5:
        print(decrypted_text)
    else:
        choose(decrypted_text)


if __name__ == "__main__":
    main()
