// atlab: 串口字节级实验工具（诊断用，不参与 modemd 运行）
//
// 用途：某些模组的"正文输入态"行为诡异（例如鼎桥 MT5700M-CN 的 AT+CMGS/AT+CMGW），
// 需要精确控制**每一个字节**（正文结束符是 Ctrl+Z 还是 CR、要不要 CRLF）并看模组原始回包。
// modemd 的 AT 层会统一追加 "\r\n"、并按行过滤，不便于做这种实验。
//
// 用法：
//
//	atlab -port /dev/ttyUSB2 -plan /tmp/plan.txt
//
// plan 文件一行一条指令：
//
//	w <hex>     发原始字节，例如 w 41540d 就是 "AT\r"
//	sleep <ms>  等待，期间照常收数据
//	dump        打印自上次 dump 起收到的原始字节（十六进制 + 可打印渲染）
//	mark <text> 打一行标记
//
// 注意：运行前必须先停掉 modemd，否则两个进程读同一个串口会互相抢数据。
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tarm/serial"
)

func main() {
	portName := flag.String("port", "/dev/ttyUSB2", "串口设备")
	baud := flag.Int("baud", 115200, "波特率")
	planPath := flag.String("plan", "", "实验脚本文件（必填）")
	flag.Parse()
	if *planPath == "" {
		fmt.Fprintln(os.Stderr, "缺少 -plan")
		os.Exit(2)
	}

	plan, err := os.ReadFile(*planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读 plan 失败: %v\n", err)
		os.Exit(1)
	}

	p, err := serial.OpenPort(&serial.Config{
		Name:        *portName,
		Baud:        *baud,
		ReadTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开 %s 失败: %v\n", *portName, err)
		os.Exit(1)
	}
	defer p.Close()
	fmt.Printf("== atlab: %s @ %d ==\n", *portName, *baud)

	rx := make(chan []byte, 256)
	go func() {
		buf := make([]byte, 512)
		for {
			n, err := p.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				rx <- chunk
			}
			if err != nil {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()

	var acc []byte
	drain := func() {
		for {
			select {
			case c := <-rx:
				acc = append(acc, c...)
			default:
				return
			}
		}
	}
	sleep := func(ms int) {
		deadline := time.Now().Add(time.Duration(ms) * time.Millisecond)
		for time.Now().Before(deadline) {
			drain()
			time.Sleep(20 * time.Millisecond)
		}
		drain()
	}
	dump := func() {
		drain()
		if len(acc) == 0 {
			fmt.Println("RX  (空)")
			return
		}
		fmt.Printf("RX  %d 字节: %s\n", len(acc), hex.EncodeToString(acc))
		fmt.Printf("    ascii: %s\n", render(acc))
		acc = nil
	}

	for _, raw := range strings.Split(string(plan), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "w":
			if len(fields) < 2 {
				fmt.Println("!! w 缺少 hex 参数")
				continue
			}
			b, err := hex.DecodeString(fields[1])
			if err != nil {
				fmt.Printf("!! hex 解析失败: %v\n", err)
				continue
			}
			if _, err := p.Write(b); err != nil {
				fmt.Printf("!! 写失败: %v\n", err)
				continue
			}
			fmt.Printf("TX  %s   (%s)\n", fields[1], render(b))
		case "sleep":
			ms := 500
			if len(fields) >= 2 {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					ms = v
				}
			}
			sleep(ms)
		case "dump":
			dump()
		case "mark":
			fmt.Printf("\n---- %s ----\n", strings.TrimSpace(strings.TrimPrefix(line, "mark")))
			dump()
		default:
			fmt.Printf("!! 未知指令: %s\n", line)
		}
	}
	sleep(200)
	dump()
	fmt.Println("== atlab 结束 ==")
}

// render 把原始字节渲染成一行可读文本（不可打印字符用 <xx> 表示）
func render(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\r':
			sb.WriteString("<CR>")
		case c == '\n':
			sb.WriteString("<LF>")
		case c == 0x1a:
			sb.WriteString("<1A>")
		case c == 0x1b:
			sb.WriteString("<ESC>")
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, "<%02X>", c)
		}
	}
	return sb.String()
}
