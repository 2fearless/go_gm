## 生成/重置秘钥对
`./main.exe -o 0`
## 加密
`./main.exe -o 1 -d xxx` xxx为需要加密的文本
## 解密
`./main.exe -o 2 -d xxxxx` xxxxx为需要解密的密文
## 签名
`./main.exe -o 3 -d xxx` xxx为签名内容
## 验签
`./main.exe -o 4 -d xxx -s zzz` xxx为签名内容 zzz为签名信息
## sm3 哈希
`./main.exe -o 5 -d xxx ` xxx为消息内容