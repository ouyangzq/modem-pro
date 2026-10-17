// catalogmodeat 给 module/kernel/modem_catalog.json 补齐"USB / PCIe 形态下切拨号模式"的 AT 指令。
//
// 数据源全部来自 **QModem**（https://github.com/FUjr/QModem）——
//
//	application/qmodem/files/usr/share/qmodem/cmds/<vendor>.sh    指令本体（cmd_* 函数里的 at "$1" "..."）
//	application/qmodem/files/usr/share/qmodem/vendor/<vendor>.sh  模式名 ↔ 参数值 的映射（get_mode / set_mode）
//
// 本地快照：d:\Go\_pdfx\qmodem\cmds_*.sh 与 vendor_*.sh（逐行核对过的就是下面这些表）。
//
// 用法（在仓库根目录）：
//
//	go run ./tools/catalogmodeat            # 写回 module/kernel/modem_catalog.json
//	go run ./tools/catalogmodeat -dry       # 只打印统计，不改文件
//
// 生成的字段（见 module/kernel/modem_catalog.go 的 ModeATSet）：
//
//	"usb_at":  { "query": "AT+QCFG=\"usbnet\"", "modes": { "qmi": "AT+QCFG=\"usbnet\",0", ... }, "note": "..." }
//	"pcie_at": { ... }   // 只有 QModem 里有 PCIe 相关指令/说明时才出现
//
// ⚠️ 只写**有取证**的东西：
//   - 某个平台 QModem 没给 set 分支（会落到默认值）⇒ 不写死，留 note 说明
//   - 某个模式 QModem 那行是注释掉的（如 gobinet、mediatek 的 mbim）⇒ 不写
//   - PCIe 形态大多数厂商只有"查询"（或干脆没有）⇒ 只写 query，并在 note 里讲清楚不下发切换
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ---- 数据模型（与 kernel.ModemCatalogEntry 对应，避免工具依赖 kernel 的解析顺序）----

type modeAT struct {
	Query string            `json:"query,omitempty"`
	Modes map[string]string `json:"modes,omitempty"`
	Note  string            `json:"note,omitempty"`
}

type entry struct {
	Vendor     string   `json:"vendor"`
	Model      string   `json:"model"`
	Platform   string   `json:"platform"`
	USB        []string `json:"usb,omitempty"`
	PCIe       []string `json:"pcie,omitempty"`
	USBModeAT  *modeAT  `json:"usb_at,omitempty"`
	PCIeModeAT *modeAT  `json:"pcie_at,omitempty"`
}

// ---- QModem 取证表 ----

// usbSwitch 一种 USB 切换方言：查询指令 + 指令模板 + 模式 → 参数
type usbSwitch struct {
	query  string
	format string            // 指令模板，里面的 %s 换成 params 里的值（foxconn 多一个前缀 %s）
	params map[string]string // 拨号模式 → 参数（只写 QModem 真的会给的那几个）
	note   string

	// build 覆盖默认的 fmt.Sprintf(format, param)，用于参数位置/个数特殊的方言（foxconn 前缀）
	build func(prefix, param string) string
}

// qmodemUSB 各厂商的 USB 拨号模式切换（按 QModem 的 vendor/<vendor>.sh set_mode() 逐条抄）
var qmodemUSB = map[string]map[string]usbSwitch{
	// 移远：cmds_quectel.sh 的 cmd_qcfg_usbnet_query/set；vendor_quectel.sh 的 get_mode/set_mode
	"quectel": {
		"qualcomm": {query: `AT+QCFG="usbnet"`, format: `AT+QCFG="usbnet",%s`,
			params: map[string]string{"qmi": "0", "ecm": "1", "mbim": "2", "rndis": "3", "ncm": "5"}},
		"lte": {query: `AT+QCFG="usbnet"`, format: `AT+QCFG="usbnet",%s`,
			params: map[string]string{"qmi": "0", "ecm": "1", "mbim": "2", "rndis": "3", "ncm": "5"}},
		"lte12": {query: `AT+QCFG="usbnet"`, format: `AT+QCFG="usbnet",%s`,
			params: map[string]string{"qmi": "0", "ecm": "1", "mbim": "2", "rndis": "3", "ncm": "5"}},
		"unisoc": {query: `AT+QCFG="usbnet"`, format: `AT+QCFG="usbnet",%s`,
			params: map[string]string{"ecm": "1", "mbim": "2", "rndis": "3", "ncm": "5"}},
		"hisilicon": {query: `AT+QCFG="usbnet"`,
			note: `Modem-Pro 的 set_mode() 没有 hisilicon 分支（会落到默认 0），参数值未取证 ⇒ 只给查询指令`},
	},
	// 广和通：cmds_fibocom.sh 的 cmd_gtusbmode_query/set；vendor_fibocom.sh 的 set_mode()
	"fibocom": {
		"qualcomm": {query: "AT+GTUSBMODE?", format: "AT+GTUSBMODE=%s",
			params: map[string]string{"qmi": "32", "ecm": "18", "mbim": "30", "rndis": "24", "ncm": "18"}},
		"lte": {query: "AT+GTUSBMODE?", format: "AT+GTUSBMODE=%s",
			params: map[string]string{"qmi": "17", "ecm": "18", "rndis": "24", "ncm": "18"}},
		"unisoc": {query: "AT+GTUSBMODE?", format: "AT+GTUSBMODE=%s",
			params: map[string]string{"ecm": "34", "mbim": "40", "rndis": "38", "ncm": "36"}},
		"mediatek": {query: "AT+GTUSBMODE?", format: "AT+GTUSBMODE=%s",
			params: map[string]string{"rndis": "41"},
			note:   "Modem-Pro 只给了 rndis=41（mbim 那行是注释掉的）"},
	},
	// 华为/鼎桥：cmds_huawei.sh 的 cmd_setmode_query/set；vendor_huawei.sh 的 set_mode()
	"huawei": {
		"unisoc": {query: "AT^SETMODE?", format: "AT^SETMODE=%s",
			params: map[string]string{"rndis": "0", "ecm": "1", "ncm": "2"}},
		"hisilicon": {query: "AT^SETMODE?", format: "AT^SETMODE=%s",
			params: map[string]string{"ecm": "0", "ncm": "4"},
			note:   "Modem-Pro 只给 ecm/ncm 两个参数；rndis(6)/mbim(7) 只在 get_mode 里能认出来"},
	},
	// 芯讯通：cmds_simcom.sh 的 cmd_cusbcfg_set_usbid / cmd_myconfig_set_usbnetmode；vendor_simcom.sh 的 set_mode()
	"simcom": {
		"qualcomm": {query: "AT+CUSBCFG?", format: "AT+CUSBCFG=usbid,1e0e,%s",
			params: map[string]string{"qmi": "9001", "rndis": "9011"},
			note:   "Modem-Pro 用 USBID 切换：qmi=0x9001、rndis=0x9011"},
		"lte": {query: "AT$MYCONFIG?", format: `AT$MYCONFIG="USBNETMODE",%s,1`,
			params: map[string]string{"rndis": "0", "ecm": "1", "auto": "2"}},
		"asrmicro": {note: "Modem-Pro 的 set_mode() 没有 asrmicro 分支 ⇒ 参数未取证，不下发"},
	},
	// 富士康：cmds_foxconn.sh 的 cmd_usbs-switch（前缀随型号：t99w640/t99w368 用 AT+，其余 AT^）
	"foxconn": {
		"qualcomm": {query: "%sUSBSWITCH?", format: "%sUSBSWITCH=%s",
			params: map[string]string{"mbim": "90d5", "rmnet": "9025"},
			build:  func(prefix, p string) string { return prefix + "USBSWITCH=" + p }},
	},
	// 泰雷兹：cmds_thales.sh 的 cmd_setconfig_query/set（USB 数据面 MBIM/RmNet）
	"thales": {
		"qualcomm": {query: "AT+SETCONFIG?", format: "AT+SETCONFIG=%s",
			params: map[string]string{"mbim": "0", "rmnet": "1"}},
	},
	// Telit：cmds_telit.sh 的 cmd_usbcfg_query/set
	"telit": {
		"qualcomm": {query: "AT#USBCFG?", format: "AT#USBCFG=%s",
			params: map[string]string{"rndis": "0", "qmi": "1", "mbim": "2", "ecm": "3"}},
	},
	// Sierra：cmds_sierra.sh 的 cmd_usbcomp_query/set（接口位掩码）
	"sierra": {
		"qualcomm": {query: "AT!USBCOMP?", format: "AT!USBCOMP=1,4,%s",
			params: map[string]string{"mbim": "0x00001009", "rmnet": "0x00000109"}},
		"lte": {query: "AT!USBCOMP?", format: "AT!USBCOMP=1,4,%s",
			params: map[string]string{"mbim": "0x00001009", "rmnet": "0x00000109"}},
	},
	// openluat：cmds_openluat.sh 的 cmd_openluat_setusb_query/set
	"openluat": {
		"unisoc": {query: "AT+SETUSB?", format: "AT+SETUSB=%s",
			params: map[string]string{"rndis": "1", "ecm": "2"}},
	},
	// 美格：cmds_meig.sh 的 cmd_ser_query/set
	"meig": {
		"qualcomm": {query: "AT+SER?", format: "AT+SER=%s,1",
			params: map[string]string{"ecm": "2", "rndis": "3", "ncm": "2"}},
		"lte": {query: "AT+SER?", format: "AT+SER=%s,1",
			params: map[string]string{"ecm": "2", "rndis": "3", "ncm": "2"}},
		"lte12": {query: "AT+SER?", format: "AT+SER=%s,1",
			params: map[string]string{"ecm": "2", "rndis": "3", "ncm": "2"}},
		"unisoc": {query: "AT+SER?", format: "AT+SER=%s,1",
			params: map[string]string{"ecm": "2", "rndis": "3", "ncm": "1"}},
	},
	// 高新兴：cmds_gosuncn.sh 的 cmd_zswitch_query/set（参数是**字符**不是数字）
	"gosuncn": {
		"qualcomm": {query: "AT+ZSWITCH?", format: "AT+ZSWITCH=%s",
			params: map[string]string{"mbim": "8", "ecm": "e", "rndis": "r", "qmi": "x"}},
		"lte": {query: "AT+ZSWITCH?", format: "AT+ZSWITCH=%s",
			params: map[string]string{"mbim": "e", "qmi": "x", "rndis": "r", "ecm": "l"}},
	},
	// 有方：QModem 的 vendor/neoway.sh 里没有 USB 模式切换（模组是固定 ECM 形态）
	"neoway": {
		"unisoc": {note: "Modem-Pro 没有提供 USB 拨号模式切换指令（该型号是固定 ECM 形态）"},
	},
}

// pcieSwitch 一种 PCIe 相关方言（QModem 里大多是"只能查"）
type pcieSwitch struct {
	query string
	note  string
}

// qmodemPCIe 各厂商的 PCIe 形态指令（QModem 的 cmds_*.sh + vendor_*.sh）。
// 外层 key = 厂商，内层 key = 平台（"" 表示该厂商的兜底说明）。
var qmodemPCIe = map[string]map[string]pcieSwitch{
	"foxconn": {
		"": {query: "%sPCIEMODE?", note: "Modem-Pro 只用它判断\"当前是否 PCIe 形态\"；切换不支持（会 disable 模式按钮）"},
	},
	"simcom": {
		"": {query: "AT+CPCIEMODE?", note: "Modem-Pro 只用它判断当前是否 PCIe 形态（EP）；切换不支持"},
	},
	"thales": {
		"": {query: "AT+MODESWITCH?", note: "手册 §15.49：AT+MODESWITCH 是 USB/PCIe 切换，参数值 Modem-Pro 未取证 ⇒ 只给查询"},
	},
	"fibocom": {
		"mediatek": {note: "MTK 平台 PCIe 走驱动（Modem-Pro 里是 mtk_pcie），没有 AT 切换指令"},
		"":         {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"},
	},
	"quectel":  {"": {note: "Modem-Pro 没有提供 Quectel 的 PCIe 形态切换指令"}},
	"huawei":   {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
	"meig":     {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
	"neoway":   {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
	"sierra":   {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
	"telit":    {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
	"openluat": {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
	"gosuncn":  {"": {note: "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"}},
}

// 该型号所在厂商/平台没有单独写说明时的兜底文案
const pcieGenericNote = "Modem-Pro 没有提供该厂商的 PCIe 形态切换指令"

// foxconnPrefix 富士康的 AT 前缀随型号变（vendor_foxconn.sh 顶部那个 case）
func foxconnPrefix(model string) string {
	switch model {
	case "t99w640", "t99w368":
		return "AT+"
	}
	return "AT^"
}

// buildUSB 生成某个型号的 usb_at（modes 只保留该型号 usb 列表里真的有的模式）
func buildUSB(model, vendor, platform string, usb []string) *modeAT {
	// 该型号**没有 USB 形态**（唯一一例：Foxconn T99W640，QModem 支持列表的 USB 列就是 ✘）：
	// 不给 usb_at —— 这里写"QModem 有参数但用不到"只会误导（它压根没有 USB 口）
	if len(usb) == 0 {
		return nil
	}
	v := qmodemUSB[vendor][platform]
	if v.query == "" && v.format == "" && v.note == "" {
		return nil
	}
	out := &modeAT{Note: v.note}
	if v.query != "" {
		out.Query = v.query
		if vendor == "foxconn" {
			out.Query = fmt.Sprintf(v.query, foxconnPrefix(model))
		}
	}
	if v.format != "" {
		prefix := ""
		if vendor == "foxconn" {
			prefix = foxconnPrefix(model)
		}
		modes := map[string]string{}
		for _, m := range usb {
			p, ok := v.params[m]
			if !ok {
				continue
			}
			if v.build != nil {
				modes[m] = v.build(prefix, p)
				continue
			}
			modes[m] = fmt.Sprintf(v.format, p)
		}
		if len(modes) > 0 {
			out.Modes = modes
		} else if len(v.params) > 0 {
			// QModem 给了参数表，但这个型号的 usb 列表里没有对应的模式（只留查询指令）
			keys := make([]string, 0, len(v.params))
			for k := range v.params {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			extra := "Modem-Pro 只给了 " + strings.Join(keys, "/") + " 的参数，该型号 usb 列表用不到 ⇒ 只给查询指令"
			if out.Note != "" {
				out.Note += "；" + extra
			} else {
				out.Note = extra
			}
		}
	}
	if out.Query == "" && out.Modes == nil && out.Note == "" {
		return nil
	}
	return out
}

// buildPCIe 生成某个型号的 pcie_at（只有 QModem 有 PCIe 相关指令/说明时才有）
func buildPCIe(model, vendor, platform string, pcie []string) *modeAT {
	if len(pcie) == 0 {
		return nil
	}
	byPlatform, ok := qmodemPCIe[vendor]
	if !ok {
		return nil
	}
	v, ok := byPlatform[platform]
	if !ok {
		v, ok = byPlatform[""]
	}
	if !ok {
		v = pcieSwitch{note: pcieGenericNote}
	}
	out := &modeAT{Note: v.note}
	if v.query != "" {
		out.Query = v.query
		if vendor == "foxconn" {
			out.Query = fmt.Sprintf(v.query, foxconnPrefix(model))
		}
	}
	return out
}

// ---- 写出（保持人可读的格式：2 空格缩进 + 数组换行）----

func writeSet(w *strings.Builder, key string, m map[string]string, indent string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "%s\"%s\": {\n", indent, key)
	for i, k := range keys {
		tail := ","
		if i == len(keys)-1 {
			tail = ""
		}
		fmt.Fprintf(w, "%s  \"%s\": %s%s\n", indent, k, jsonStr(m[k]), tail)
	}
	fmt.Fprintf(w, "%s}", indent)
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writeModeAT(w *strings.Builder, key string, m *modeAT, indent string) {
	if m == nil {
		return
	}
	fmt.Fprintf(w, ",\n%s\"%s\": {\n", indent, key)
	parts := []string{}
	if m.Query != "" {
		parts = append(parts, indent+"  \"query\": "+jsonStr(m.Query))
	}
	if len(m.Modes) > 0 {
		var sub strings.Builder
		writeSet(&sub, "modes", m.Modes, indent+"  ")
		parts = append(parts, sub.String())
	}
	if m.Note != "" {
		parts = append(parts, indent+"  \"note\": "+jsonStr(m.Note))
	}
	fmt.Fprint(w, strings.Join(parts, ",\n"))
	fmt.Fprintf(w, "\n%s}", indent)
}

func writeStringArray(w *strings.Builder, key string, vals []string, indent string) {
	fmt.Fprintf(w, "%s\"%s\": [\n", indent, key)
	for i, v := range vals {
		tail := ","
		if i == len(vals)-1 {
			tail = ""
		}
		fmt.Fprintf(w, "%s  %s%s\n", indent, jsonStr(v), tail)
	}
	fmt.Fprintf(w, "%s]", indent)
}

func main() {
	dry := flag.Bool("dry", false, "只统计，不写文件")
	flag.Parse()

	// ⚠️ catalog 已搬到 module/catalog（kernel 里那份是别名层，不再是数据文件）。
	path := "module/catalog/modem_catalog.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读不到", path, err)
		os.Exit(1)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var list []entry
	if err := dec.Decode(&list); err != nil {
		fmt.Fprintln(os.Stderr, "解析失败：", err)
		os.Exit(1)
	}

	usbCov, pcieCov, noUSB := 0, 0, 0
	var w strings.Builder
	w.WriteString("[\n")
	for i := range list {
		e := &list[i]
		e.USBModeAT = buildUSB(e.Model, e.Vendor, e.Platform, e.USB)
		e.PCIeModeAT = buildPCIe(e.Model, e.Vendor, e.Platform, e.PCIe)
		if e.USBModeAT != nil && len(e.USBModeAT.Modes) > 0 {
			usbCov++
		} else {
			noUSB++
		}
		if e.PCIeModeAT != nil {
			pcieCov++
		}

		fmt.Fprintf(&w, "  {\n")
		fmt.Fprintf(&w, "    \"vendor\": %s,\n", jsonStr(e.Vendor))
		fmt.Fprintf(&w, "    \"model\": %s,\n", jsonStr(e.Model))
		fmt.Fprintf(&w, "    \"platform\": %s", jsonStr(e.Platform))
		if len(e.USB) > 0 {
			fmt.Fprintf(&w, ",\n")
			writeStringArray(&w, "usb", e.USB, "    ")
		}
		if len(e.PCIe) > 0 {
			fmt.Fprintf(&w, ",\n")
			writeStringArray(&w, "pcie", e.PCIe, "    ")
		}
		writeModeAT(&w, "usb_at", e.USBModeAT, "    ")
		writeModeAT(&w, "pcie_at", e.PCIeModeAT, "    ")
		fmt.Fprintf(&w, "\n  }")
		if i != len(list)-1 {
			w.WriteString(",")
		}
		w.WriteString("\n")
	}
	w.WriteString("]\n")

	fmt.Printf("型号 %d 个：USB 拨号模式指令覆盖 %d、无指令 %d；PCIe 说明 %d\n",
		len(list), usbCov, noUSB, pcieCov)
	if *dry {
		return
	}
	if err := os.WriteFile(path, []byte(w.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写回失败：", err)
		os.Exit(1)
	}
	fmt.Println("已写回", path)
}
