package main

import (
	"github.com/gin-gonic/gin"
	"sm2/gm"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		o := c.DefaultQuery("o", "99")
		data := c.DefaultQuery("d", "")
		sign := c.DefaultQuery("s", "")
		salt := "1234567812345678"
		var result string
		switch o {
		case "0":
			//重置秘钥
			result = gm.Cmd1()
			//fmt.Println("秘钥对已重置")
		case "1":
			//加密
			result = gm.Cmd2(data)
		case "2":
			//解密
			result = gm.Cmd3(data)
		case "3":
			result = gm.Cmd4(data, salt)
		case "4":
			result = gm.Cmd5(data, sign, salt)
		case "5":
			result = gm.Cmd6(data)
		default:
			result = "参数错误"
		}
		c.JSON(200, gin.H{
			"result": result,
			"o":      o,
			"d":      data,
			"s":      sign,
		})
	})
	r.Run(":8989") // listen and serve on 0.0.0.0:8080
}
