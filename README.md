### hyperota

一个简单的 HyperOS 更新链接获取脚本

目前来看通过明文只能获取正式版最新版本的快速下载链接及以往版本的慢速下载链接

无法获取开发版链接，需要继续分析系统更新中 ArrayMap<>() 中的 q, t, s 来源

```
Requirements: pycryptodome, requests

Usage: hyperota.py codename miui_version android_version

Example: hyperota.py houji OS1.0.16.0.UNCCNXM 14
```


参考来源: https://github.com/HegeKen/MRData/blob/master/script/test2.py
