## 生成/重置秘钥对
`./sm2.exe -o 0`
## 加密
`./sm2.exe -o 1 -d xxx` xxx为需要加密的文本
## 解密
`./sm2.exe -o 2 -d xxxxx` xxxxx为需要解密的密文
## 签名
`./sm2.exe -o 3 -d xxx` xxx为签名内容
## 验签
`./sm2.exe -o 4 -d xxx -s zzz` xxx为签名内容 zzz为签名信息