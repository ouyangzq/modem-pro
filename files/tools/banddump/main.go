package main

// ====================== banddump：生成 module/kernel/modem_bands.json ======================
//
// 从 **QModem 仓库** 的 `application/qmodem/files/usr/share/qmodem/modem_support.json`
// 提取"每个型号支持哪些频段"，写成 `module/kernel/modem_bands.json`（供 modemd 的 API / UI 使用）。
//
// 为什么要单独一个工具：
//
//	① 上游一更新，我们必须能**一次重跑**而不是手抄 91 个型号的四组频段；
//	② 频段数据的"上游字段名"（wcdma_band/lte_band/nsa_band/sa_band）只在这一处出现，
//	   换字段名时改这里就够了；kernel 只认我们自己的字段（wcdma/lte/nr_nsa/nr_sa）；
//	③ 顺手做**对齐检查**：我们的支持清单（`module/kernel/modem_catalog.json`）与上游频段表的
//	   型号集合应该一一对应，缺哪个/多哪个当场打印出来。
//
// 用法（仓库根目录）：
//
//	go run ./tools/banddump
//	go run ./tools/banddump -src d:\Go\_pdfx\qmodem\modem_support.json -out module/kernel/modem_bands.json
//
// ⚠️ 取值形态是上游的口径：`1/3/5/8/34/38/39/40/41` 这种斜杠分隔；`"0"` = 无（丢弃）；
// 字段缺失 = 上游**没写**（保留空数组，界面要能区分"没写"与"不支持"）。
// 生成的文件由 `module/kernel/modem_bands_test.go` 校验（值域/升序/去重/与清单对齐）。

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 默认路径（相对仓库根 `d:\Go\5g-modem-manager`）
//
// ⚠️ catalog 已搬到 module/catalog（kernel 里那份是别名层，不再是数据文件）。
const (
	defaultSrc = `d:\Go\_pdfx\qmodem\modem_support.json`
	defaultOut = `kernel\modem_bands.json`
	defaultCat = `module\catalog\modem_catalog.json`
)

// upstreamRec 上游 modem_support.json 里单个型号的记录（只取我们要的字段）
type upstreamRec struct {
	Manufacturer string `json:"manufacturer"`
	Platform     string `json:"platform"`
	WCDMABand    string `json:"wcdma_band"`
	LTEBand      string `json:"lte_band"`
	NSABand      string `json:"nsa_band"`
	SABand       string `json:"sa_band"`
}

// bandOut 输出记录（字段名与 bands.ModemBands 的 json tag 一致）
type bandOut struct {
	Model    string `json:"model"`
	Vendor   string `json:"vendor"`
	Platform string `json:"platform"`
	WCDMA    []int  `json:"wcdma,omitempty"`
	LTE      []int  `json:"lte,omitempty"`
	NRNSA    []int  `json:"nr_nsa,omitempty"`
	NRSA     []int  `json:"nr_sa,omitempty"`
}

// catalogEntry 支持清单里的一行（只要型号，用来定顺序 + 对齐检查）
type catalogEntry struct {
	Model string `json:"model"`
}

func main() {
	src := flag.String("src", defaultSrc, "QModem modem_support.json 路径")
	out := flag.String("out", defaultOut, "输出的 module/kernel/modem_bands.json 路径")
	cat := flag.String("catalog", defaultCat, "module/catalog/modem_catalog.json 路径（定顺序 + 对齐检查）")
	flag.Parse()

	raw, err := os.ReadFile(*src)
	if err != nil {
		fatal("读源文件 %s 失败：%v", *src, err)
	}
	var doc struct {
		ModemSupport map[string]map[string]upstreamRec `json:"modem_support"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fatal("解析源文件失败：%v", err)
	}
	if len(doc.ModemSupport["usb"]) == 0 {
		fatal("源文件里 modem_support.usb 是空的 —— 路径对吗？（%s）", *src)
	}

	// 型号 → 记录：usb 优先，pcie 补齐（同一型号两边都有时以 usb 为准；
	// 实测只有 rm500s-ce 的 pcie 记录缺频段字段，取 usb 的那份是对的）
	records := map[string]upstreamRec{}
	var ifaceOf = map[string]string{}
	for _, iface := range []string{"usb", "pcie"} {
		for _, m := range sortedKeys(doc.ModemSupport[iface]) {
			if _, ok := records[m]; !ok {
				records[m] = doc.ModemSupport[iface][m]
				ifaceOf[m] = iface
			}
		}
	}

	// 顺序对齐支持清单（= QModem 支持列表的分组顺序），清单里没有的上游型号追加在后面
	var order []string
	inCatalog := map[string]bool{}
	if b, err := os.ReadFile(*cat); err == nil {
		var entries []catalogEntry
		if err := json.Unmarshal(b, &entries); err != nil {
			fatal("解析 %s 失败：%v", *cat, err)
		}
		for _, e := range entries {
			order = append(order, e.Model)
			inCatalog[e.Model] = true
		}
	} else {
		fmt.Fprintf(os.Stderr, "⚠️ 读不到 %s（%v）：改按上游顺序输出\n", *cat, err)
	}
	var extra, missing []string
	for _, m := range sortedKeys(records) {
		if !inCatalog[m] {
			if len(order) > 0 { // 只有读到清单时才谈"多出来的"
				extra = append(extra, m)
			}
			order = append(order, m)
		}
	}
	for _, m := range order {
		if _, ok := records[m]; !ok && inCatalog[m] {
			missing = append(missing, m)
		}
	}

	outRecords := make([]bandOut, 0, len(order))
	withBands, withNR := 0, 0
	for _, m := range order {
		r := records[m]
		rec := bandOut{
			Model: m, Vendor: r.Manufacturer, Platform: r.Platform,
			WCDMA: parseBands(r.WCDMABand), LTE: parseBands(r.LTEBand),
			NRNSA: parseBands(r.NSABand), NRSA: parseBands(r.SABand),
		}
		if len(rec.WCDMA)+len(rec.LTE)+len(rec.NRNSA)+len(rec.NRSA) > 0 {
			withBands++
		}
		if len(rec.NRNSA)+len(rec.NRSA) > 0 {
			withNR++
		}
		outRecords = append(outRecords, rec)
	}

	b, err := json.MarshalIndent(outRecords, "", "  ")
	if err != nil {
		fatal("序列化失败：%v", err)
	}
	// MarshalIndent 会把每个频段号排成一行（39 KB → 12 KB 的差别，且人工核对上游更新时
	// 希望"一个型号几行"），所以把**纯数字数组**折叠成一行：`[1, 3, 5, 8]`
	b = compactIntArrays(b)
	b = append(b, '\n')
	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatal("建目录失败：%v", err)
		}
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fatal("写 %s 失败：%v", *out, err)
	}

	fmt.Printf("✅ %s：%d 个型号（有频段 %d、支持 NR %d），%d 字节\n", *out, len(outRecords), withBands, withNR, len(b))
	fmt.Printf("   来源 %s（usb %d 个 / pcie %d 个 记录）\n", *src, len(doc.ModemSupport["usb"]), len(doc.ModemSupport["pcie"]))
	if len(missing) > 0 {
		fmt.Printf("⚠️ 我们的支持清单里有、上游频段表里没有的型号（%d）：%s\n", len(missing), strings.Join(missing, ", "))
		fmt.Println("   → 这些型号在界面/接口上会显示「上游没有频段记录」；上游补上后重跑本工具即可")
	}
	if len(extra) > 0 {
		fmt.Printf("⚠️ 上游频段表里有、我们的支持清单里没有的型号（%d）：%s\n", len(extra), strings.Join(extra, ", "))
		fmt.Println("   → 先确认要不要接进清单（module/kernel/modem_catalog.json），再接的话两边一起补")
	}
	if len(missing) == 0 && len(extra) == 0 {
		fmt.Println("   型号集合与支持清单完全一致 ✓")
	}
}

// compactIntArrays 把缩进后的**纯数字数组**折叠成一行：`[\n 1,\n 3\n]` → `[1, 3]`
//
// 只认"整个数组里只有数字与逗号/空白"的形态，所以不会误伤别的数组（本文件也只有频段数组）。
func compactIntArrays(b []byte) []byte {
	re := regexp.MustCompile(`\[(?:\s*\d+\s*,)*\s*\d+\s*\]`)
	return re.ReplaceAllFunc(b, func(m []byte) []byte {
		nums := strings.FieldsFunc(string(m), func(r rune) bool {
			return r == '[' || r == ']' || r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
		})
		return []byte("[" + strings.Join(nums, ", ") + "]")
	})
}

// parseBands 上游频段串 → 升序去重的频段号（`1/3/5`；`0` 与非法项丢弃）
func parseBands(s string) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '/' || r == ',' || r == ' ' || r == ';' || r == '|'
	}) {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n <= 0 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "❌ "+format+"\n", args...)
	os.Exit(1)
}
