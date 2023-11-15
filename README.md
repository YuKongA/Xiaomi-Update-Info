### Xiaomi Update Info

一个简单的 HyperOS/MIUI 更新链接获取脚本

通过 s:"1" 方式只能获取正式版下载链接，无法获取开发版链接，如需获取请自行使用 s:"2"获取，这需要对应的 securityKey 和 token

```
Requirements: pycryptodome, requests

Usage: XiaomiUpdateInfo.py codename rom_version android_version

Example: 
(1) XiaomiUpdateInfo.py houji OS1.0.29.0.UNCCNXM 14
(2) XiaomiUpdateInfo.py fuxi V14.0.5.0.UMCCNXM 14
```


参考来源: 
https://github.com/HegeKen/MRData/blob/master/script/test2.py

实例：
<p><img alt="Demo.png" src="Demo.png"></p>