package main

import (
	"flag"
	"fmt"
	"sm2/gm"
)

func main() {
	var opt int
	var data string
	var sign string
	flag.IntVar(&opt, "o", 1, "操作方式")
	flag.StringVar(&data, "d", "", "数据")
	flag.StringVar(&sign, "s", "", "签名")
	salt := "1234567812345678"
	flag.Parse()
	switch opt {
	case 0:
		//重置秘钥
		fmt.Println(gm.Cmd1())
		//fmt.Println("秘钥对已重置")
	case 1:
		//加密
		fmt.Println(gm.Cmd2(data))
	case 2:
		//解密
		fmt.Println(gm.Cmd3(data))
	case 3:
		fmt.Println(gm.Cmd4(data, salt))
	case 4:
		fmt.Println(gm.Cmd5(data, sign, salt))
	case 5:
		fmt.Println(gm.Cmd6(data))
	default:
		fmt.Println("参数错误")
	}
}
