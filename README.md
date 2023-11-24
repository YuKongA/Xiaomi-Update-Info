![Xiaomi-Update-Info](https://socialify.git.ci/YuKongA/Xiaomi-Update-Info/image?description=1&descriptionEditable=%E4%B8%80%E4%B8%AA%E7%AE%80%E5%8D%95%E7%9A%84%20HyperOS%2FMIUI%20%E6%9B%B4%E6%96%B0%E9%93%BE%E6%8E%A5%E8%8E%B7%E5%8F%96%E8%84%9A%E6%9C%AC&font=Inter&language=1&name=1&owner=1&pattern=Plus&theme=Auto)

## Notes:

通过 v1 接口只能获取正式版下载链接，要获取开发版下载链接请登陆拥有权限的账号使用 v2 接口

## Usage:
```
Requirements: 
// 安装必要依赖包
pip install --upgrade -r requirements.txt 

Usage:
// 登录小米账号，使用 v1 接口无需登录
XiaomiCommunity.py account password

// 对应：设备代号 系统版本 安卓版本
XiaomiUpdateInfo.py codename rom_version android_version

Example:
// 正式版，无需登录，不需要用户权限
(1) XiaomiUpdateInfo.py houji OS1.0.20.0.UNCCNXM 14

// 开发版，需登录，需要对应用户权限
(2) XiaomiUpdateInfo.py houji OS1.0.23.11.13.DEV 14
```

## Credits:

(1) [XiaoMiToolV2](https://github.com/francescotescari/XiaoMiToolV2)

(2) [Xiaomi-Community-AutoTask](https://github.com/CMDQ8575/Xiaomi-Community-AutoTask)

## More:

关于**设备代号**(_"codename"_)，请参阅：
[小米手机型号汇总](https://github.com/KHwang9883/MobileModels/blob/master/brands/xiaomi.md)