# crack-navicat-offline
在渗透过程在目标机器上抓取密码总是有些不保险，那么可以尝试将密码导出，离线爆破。本脚本实现解析导出注册表，并解密导出的navicat密码。

参考 [how-does-navicat-encrypt-password](https://github.com/HyperSine/how-does-navicat-encrypt-password)

# Usage
导出注册表
```powershell
reg export HKEY_CURRENT_USER\Software\PremiumSoft C:\Users\WangJuan.MOTOO\desktop\reg.reg
```

![](https://i.loli.net/2020/11/26/fVzolKNCcJsxd7G.png)

运行脚本


![](https://i.loli.net/2020/11/26/l2AVZO4rtWT6Re3.png)

