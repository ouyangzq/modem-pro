// mkipk - 打包 OpenWrt 的 .ipk 安装包（纯 Go 实现，Windows 上也能用）
//
// ipk 就是「ar 归档」里装三个成员：
//
//	!<arch>
//	debian-binary   内容固定 "2.0\n"
//	control.tar.gz  ./control（+ 可选的 postinst / prerm / conffiles…）
//	data.tar.gz     ./usr/bin/modemd、./etc/... 等要安装的文件
//
// 为什么不用系统工具：Windows 上没有 ar，.NET Framework 也没有 tar 写入器。
// 用 Go 标准库（archive/tar + compress/gzip + 自己拼 ar 头）能保证
// 在任何平台、离线环境下生成同样结构的包。
//
// 用法（独立命令行工具）：
//
//	go run ./tools/mkipk \
//	  -data build/ipk/aarch64/data \
//	  -control build/ipk/aarch64/control \
//	  -package modemd -version 0.1.0-1 -arch aarch64_cortex-a53 \
//	  -section net -priority optional -maintainer "you <you@example.com>" \
//	  -description "5G modem manager" -description-line "多模组 / Web 调试台" \
//	  -conffiles "etc/modemd/config.toml" \
//	  -exec "usr/bin/modemd,etc/init.d/modemd" \
//	  -out build/modemd_0.1.0-1_aarch64_cortex-a53.ipk
//
// 查看一个已有 ipk 的结构（自检用）：
//
//	go run ./tools/mkipk -list build/xxx.ipk -deep
//
// ⚠️ -conffiles 会被写成 control.tar.gz 里的 ./conffiles（绝对路径、每行一个）：
// 漏了它 opkg 就不把 /etc/... 当配置文件，升级会**覆盖用户改过的配置**。
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	var (
		dataDir    = flag.String("data", "", "要打包的根目录（映射到 /）")
		ctrlDir    = flag.String("control", "", "control 附加文件目录（postinst/prerm/conffiles…），可空")
		pkg        = flag.String("package", "modemd", "包名")
		version    = flag.String("version", "0.1.0-1", "版本（OpenWrt 惯例 upstream-pkgrel）")
		arch       = flag.String("arch", "", "OpenWrt 架构串，如 aarch64_cortex-a53（必填）")
		section    = flag.String("section", "net", "Section")
		priority   = flag.String("priority", "optional", "Priority")
		depends    = flag.String("depends", "", "Depends（逗号分隔，可空）")
		provides   = flag.String("provides", "", "Provides（逗号分隔，可空）")
		conflicts  = flag.String("conflicts", "", "Conflicts（逗号分隔，可空；改名后用来换掉旧包名）")
		replaces   = flag.String("replaces", "", "Replaces（逗号分隔，可空；声明本包接手旧包的文件）")
		maintainer = flag.String("maintainer", "modemd", "Maintainer")
		desc       = flag.String("description", "", "短描述（第一行）")
		descLines  = flag.String("description-line", "", "描述附加行，用 | 分隔")
		conffiles  = flag.String("conffiles", "", "配置文件列表（逗号分隔，相对/绝对都行）：会写进 control.tar.gz 的 ./conffiles，opkg 升级时据此保留用户改过的那份")
		execs      = flag.String("exec", "", "需要可执行位的相对路径（逗号分隔）；usr/bin 与 etc/init.d 下的文件默认就是 0755")
		out        = flag.String("out", "", "输出 ipk 路径（必填）")
		listMode   = flag.Bool("list", false, "改为列出已有 ipk 的结构")
		deep       = flag.Bool("deep", false, "与 -list 搭配：再列出包内文件清单")
		mtimeStr   = flag.String("mtime", "", "归档时间戳（unix 秒）；默认取 SOURCE_DATE_EPOCH 或当前时间")
		format     = flag.String("format", "ipkg", "输出格式：ipkg（默认，gzip 的 tar，OpenWrt/opkg 认这个）| ar（Debian .deb 那种）")
	)
	flag.Parse()

	if *listMode {
		target := *out
		if flag.NArg() > 0 {
			target = flag.Arg(0)
		}
		// Go 的 flag 遇到第一个非 flag 参数就停止解析，所以 `-list a.ipk -deep`
		// 里的 -deep 会落到 Args() 里 —— 这里补一刀，两种顺序都认。
		if !*deep {
			for _, a := range flag.Args() {
				if a == "-deep" || a == "--deep" {
					*deep = true
				}
			}
		}
		if target == "" {
			fatal("-list 需要给出 ipk 路径")
		}
		if err := listIPK(target, *deep); err != nil {
			fatal("%v", err)
		}
		return
	}

	if *dataDir == "" || *out == "" || *arch == "" {
		fatal("-data / -out / -arch 都是必填")
	}

	mtime := time.Now()
	if *mtimeStr != "" {
		if sec, err := strconv.ParseInt(*mtimeStr, 10, 64); err == nil {
			mtime = time.Unix(sec, 0)
		}
	} else if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			mtime = time.Unix(sec, 0).UTC()
		}
	}

	spec := controlSpec{
		pkg: *pkg, version: *version, arch: *arch, section: *section,
		priority: *priority, depends: *depends, maintainer: *maintainer,
		provides: *provides, conflicts: *conflicts, replaces: *replaces,
		desc: *desc, descLines: splitList(*descLines, "|"), conffiles: splitList(*conffiles, ","),
		dataDir: *dataDir,
	}
	ctrlTGZ, err := packControlTGZ(*ctrlDir, spec, mtime)
	if err != nil {
		fatal("打包 control.tar.gz 失败: %v", err)
	}
	dataTGZ, nFiles, err := tarGzDir(*dataDir, nil, splitList(*execs, ","), mtime, false)
	if err != nil {
		fatal("打包 data.tar.gz 失败: %v", err)
	}

	var ipk []byte
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "ipkg", "tar", "tgz":
		ipk, err = ipkgArchive(dataTGZ, ctrlTGZ, mtime)
		if err != nil {
			fatal("组装 ipkg 失败: %v", err)
		}
	case "ar":
		ipk, err = arArchive([]arMember{
			{name: "debian-binary", data: []byte("2.0\n"), mode: 0o644},
			{name: "control.tar.gz", data: ctrlTGZ, mode: 0o644},
			{name: "data.tar.gz", data: dataTGZ, mode: 0o644},
		}, mtime)
		if err != nil {
			fatal("组装 ar 失败: %v", err)
		}
	default:
		fatal("未知的 -format %q（可选 ipkg | ar）", *format)
	}

	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatal("创建输出目录失败: %v", err)
		}
	}
	if err := os.WriteFile(*out, ipk, 0o644); err != nil {
		fatal("写 ipk 失败: %v", err)
	}

	fmt.Printf("package   : %s\n", *pkg)
	fmt.Printf("version   : %s\n", *version)
	fmt.Printf("arch      : %s\n", *arch)
	fmt.Printf("format    : %s\n", strings.ToLower(strings.TrimSpace(*format)))
	fmt.Printf("files     : %d\n", nFiles)
	fmt.Printf("size      : %s (control.tar.gz %s + data.tar.gz %s)\n",
		humanSize(len(ipk)), humanSize(len(ctrlTGZ)), humanSize(len(dataTGZ)))
	fmt.Printf("output    : %s\n", *out)
}

// ---------------------------------------------------------------- control ----

type controlSpec struct {
	pkg, version, arch, section, priority, depends, maintainer, desc string
	provides, conflicts, replaces                                    string
	descLines, conffiles                                             []string
	dataDir                                                          string
}

// controlFile 生成 control 文本。字段顺序按 OpenWrt 惯例，
// 描述用「第一行短描述 + 后续行缩进一个空格」的多行格式。
// packControlTGZ 打包 control.tar.gz：control 字段 + ./conffiles + 目录里的 postinst/prerm 等。
func packControlTGZ(ctrlDir string, spec controlSpec, mtime time.Time) ([]byte, error) {
	control, err := buildControl(spec)
	if err != nil {
		return nil, err
	}
	extra := map[string][]byte{"control": control}
	if cf := conffilesBytes(spec.conffiles); len(cf) > 0 {
		extra["conffiles"] = cf
	}
	tgz, _, err := tarGzDir(ctrlDir, extra, nil, mtime, true)
	if err != nil {
		return nil, err
	}
	return tgz, nil
}

// conffilesBytes 生成 control.tar.gz 里的 ./conffiles（一行一个**绝对**路径）。
//
// ⚠️ 为什么必须有这个文件：opkg 只有在 control 里看到 conffiles 时才会把
// /etc/... 当配置文件处理 —— 升级时**保留用户改过的那份**（新版另存为 <file>-opkg）。
// 以前 mkipk 收了 -conffiles 参数却没写进包，于是每次 `opkg install` 都用包里的
// 默认 config.toml 覆盖设备上的：微信机器人凭据、推送开关、访问密码全丢，
// 表现就是"每次升级都要重新扫码登录"（2026-10-01 真机定位）。
//
// 传进来的相对路径（`etc/modemd/config.toml`）会规范成绝对路径，因为 opkg 按
// "/" 开头的绝对路径匹配列表。
func conffilesBytes(list []string) []byte {
	seen := map[string]bool{}
	var out []string
	for _, e := range list {
		p := strings.TrimSpace(e)
		if p == "" {
			continue
		}
		p = "/" + path.Clean(strings.TrimPrefix(p, "/"))
		// 防呆：clean 之后还在往上跳、或落到根目录（"/" / "/."）的，一律丢掉
		if p == "/" || p == "/." || strings.HasPrefix(p, "/..") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return []byte(strings.Join(out, "\n") + "\n")
}

func buildControl(c controlSpec) ([]byte, error) {
	instSize, err := dirSizeKB(c.dataDir)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Package: %s\n", c.pkg)
	fmt.Fprintf(&b, "Version: %s\n", c.version)
	if c.depends != "" {
		fmt.Fprintf(&b, "Depends: %s\n", strings.Join(splitList(c.depends, ","), ", "))
	}
	if c.provides != "" {
		fmt.Fprintf(&b, "Provides: %s\n", strings.Join(splitList(c.provides, ","), ", "))
	}
	if c.conflicts != "" {
		fmt.Fprintf(&b, "Conflicts: %s\n", strings.Join(splitList(c.conflicts, ","), ", "))
	}
	if c.replaces != "" {
		fmt.Fprintf(&b, "Replaces: %s\n", strings.Join(splitList(c.replaces, ","), ", "))
	}
	fmt.Fprintf(&b, "Section: %s\n", c.section)
	fmt.Fprintf(&b, "Priority: %s\n", c.priority)
	fmt.Fprintf(&b, "Maintainer: %s\n", c.maintainer)
	fmt.Fprintf(&b, "Architecture: %s\n", c.arch)
	fmt.Fprintf(&b, "Installed-Size: %d\n", instSize)
	desc := c.desc
	if desc == "" {
		desc = c.pkg
	}
	fmt.Fprintf(&b, "Description: %s\n", desc)
	for _, line := range c.descLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Fprintf(&b, " %s\n", line)
	}
	// 空行结尾：opkg 解析多行描述时靠"下一行不以空格开头"来结束
	return []byte(b.String()), nil
}

// ---------------------------------------------------------------- tar.gz -----

// tarGzDir 把目录打成 tar.gz（条目名以 "./" 开头，符合 opkg 习惯）。
// extra 是额外插入的文件（例如 control），文件名为 "./<name>"。
// execList 指定需要 0755 的路径；usr/bin 与 etc/init.d 下的文件默认 0755。
func tarGzDir(dir string, extra map[string][]byte, execList []string, mtime time.Time, isControl bool) ([]byte, int, error) {
	// 只给了 control 文件（不带 postinst/prerm 那一类目录）时目录可能不存在：
	// 当成空目录，而不是报错退出。
	if dir != "" {
		if _, err := os.Stat(dir); err != nil {
			dir = ""
		}
	}
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	mtime = mtime.Truncate(time.Second) // USTAR 只能到秒
	gz.Header.ModTime = mtime
	tw := tar.NewWriter(gz)

	exec := map[string]bool{}
	for _, e := range splitList(strings.Join(execList, ","), ",") {
		exec[path.Clean(strings.TrimPrefix(e, "./"))] = true
	}
	isExec := func(rel string) bool {
		if exec[rel] {
			return true
		}
		// ⚠️ control 里的脚本必须是 0755：opkg 会**直接执行**它们
		// （/bin/sh: //usr/lib/opkg/info/<pkg>.postinst: Permission denied，退出码 126 ——
		// 真机踩过：包装上了，但 postinst 没跑，服务没 enable 也没起）。
		if isControl && (rel == "preinst" || rel == "postinst" || rel == "prerm" || rel == "postrm") {
			return true
		}
		return strings.HasPrefix(rel, "usr/bin/") || strings.HasPrefix(rel, "etc/init.d/")
	}

	count := 0
	names := make([]string, 0, len(extra))
	for n := range extra {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		hdr := &tar.Header{
			Name: "./" + n, Mode: 0o644, Size: int64(len(extra[n])),
			ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root",
		}
		if isExec(n) {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, 0, err
		}
		if _, err := tw.Write(extra[n]); err != nil {
			return nil, 0, err
		}
		count++
	}

	if dir != "" {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			rel = path.Clean(strings.ReplaceAll(rel, `\`, "/"))
			if rel == "." {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			hdr := &tar.Header{
				Name: "./" + rel, ModTime: mtime, Uid: 0, Gid: 0,
				Uname: "root", Gname: "root", Format: tar.FormatUSTAR,
			}
			if d.IsDir() {
				hdr.Name += "/"
				hdr.Typeflag = tar.TypeDir
				hdr.Mode = 0o755
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
				return nil
			}
			hdr.Typeflag = tar.TypeReg
			hdr.Mode = 0o644
			if isExec(rel) {
				hdr.Mode = 0o755
			}
			hdr.Size = info.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
			count++
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), count, nil
}

// ------------------------------------------------------------- ipkg ------

// ipkgArchive 组装 OpenWrt 真正能装的 .ipk：**gzip 过的 tar**，里面三样：
// ./debian-binary（"2.0\n"）、./data.tar.gz、./control.tar.gz（顺序与官方 feed 的包一致）。
//
// ⚠️ 为什么不是 ar：OpenWrt 23.05 上的 opkg-lede 拿到 ar 会直接报
// `pkg_init_from_file: Malformed package file`（真机实测，2026-09-30）。
// 官方 feeds 里的 .ipk 解开就是这个 gzip-tar 结构。
//
// ⚠️ tar 头必须能被 USTAR 表达（名字短、时间戳整秒）—— 否则 Go 会插 PAX 扩展头，
// 而设备上的 tar/opkg 解析器未必认。
func ipkgArchive(dataTGZ, ctrlTGZ []byte, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	gz.Header.ModTime = mtime.Truncate(time.Second)
	tw := tar.NewWriter(gz)

	sec := mtime.Truncate(time.Second)
	add := func(name string, data []byte) error {
		hdr := &tar.Header{
			Name: "./" + name, Mode: 0o644, Size: int64(len(data)),
			ModTime: sec, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root",
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := add("debian-binary", []byte("2.0\n")); err != nil {
		return nil, err
	}
	if err := add("data.tar.gz", dataTGZ); err != nil {
		return nil, err
	}
	if err := add("control.tar.gz", ctrlTGZ); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ------------------------------------------------------------------- ar ------

type arMember struct {
	name string
	data []byte
	mode int64
}

// arArchive 生成 classic ar（就是 .deb/.ipk 用的那种）：文件头 60 字节纯文本，
// 数据按偶数长度对齐（不足补 '\n'）。名字用空格填充、不加斜杠（与 Debian 的 .deb 一致）。
func arArchive(members []arMember, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, m := range members {
		if len(m.name) > 15 {
			return nil, fmt.Errorf("ar 成员名太长: %s", m.name)
		}
		size := len(m.data)
		hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n",
			m.name, mtime.Unix(), 0, 0, fmt.Sprintf("%o", m.mode), size)
		if len(hdr) != 60 {
			return nil, fmt.Errorf("ar 头长度不对: %d", len(hdr))
		}
		buf.WriteString(hdr)
		buf.Write(m.data)
		if size%2 == 1 { // 奇数字节要补一个 '\n'
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), nil
}

// ------------------------------------------------------------------ 自检 ------

// listIPK 打印 ipk 结构（-deep 时再解开 control/data 列出文件清单）。
// 两种格式都认：**ipkg（gzip 的 tar，OpenWrt 用）** 与 ar（Debian .deb 那种）。
func listIPK(file string, deep bool) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	fmt.Printf("%s  (%s)\n", file, humanSize(len(raw)))
	switch {
	case len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b:
		fmt.Printf("  format: ipkg（gzip 的 tar）—— OpenWrt 的 opkg 认这个\n")
		return listIPKG(raw, deep)
	case len(raw) >= 8 && string(raw[:8]) == "!<arch>\n":
		fmt.Printf("  format: ar —— ⚠️ OpenWrt 的 opkg 可能报 Malformed package file\n")
		return listAr(raw, deep)
	}
	return fmt.Errorf("%s 既不是 gzip-tar（ipkg）也不是 ar 归档", file)
}

// listIPKG 列出 ipkg（gzip 的 tar）结构
func listIPKG(raw []byte, deep bool) error {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("不是合法的 gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读 tar 失败: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return fmt.Errorf("读成员 %s 失败: %v", hdr.Name, err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		fmt.Printf("  %-16s %10s  %s\n", name, humanSize(len(body)), describeMember(name, body))
		if !deep || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		entries, err := tarGzEntries(body)
		if err != nil {
			fmt.Printf("      (解包失败: %v)\n", err)
			continue
		}
		for _, e := range entries {
			fmt.Printf("      %s\n", e)
		}
	}
	return nil
}

// listAr 列出 ar 归档结构（老的 .deb 风格 ipk）
func listAr(raw []byte, deep bool) error {
	off := 8
	for off+60 <= len(raw) {
		hdr := raw[off : off+60]
		if string(hdr[58:60]) != "`\n" {
			return fmt.Errorf("第 %d 字节处的 ar 头损坏", off)
		}
		name := strings.TrimRight(string(hdr[0:16]), " /")
		size, err := strconv.Atoi(strings.TrimSpace(string(hdr[48:58])))
		if err != nil {
			return fmt.Errorf("ar 头里的长度解析失败: %q", string(hdr[48:58]))
		}
		off += 60
		if off+size > len(raw) {
			return fmt.Errorf("成员 %s 超出文件长度", name)
		}
		body := raw[off : off+size]
		off += size + size%2

		fmt.Printf("  %-16s %10s  %s\n", name, humanSize(size), describeMember(name, body))
		if !deep || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		entries, err := tarGzEntries(body)
		if err != nil {
			fmt.Printf("      (解包失败: %v)\n", err)
			continue
		}
		for _, e := range entries {
			fmt.Printf("      %s\n", e)
		}
	}
	return nil
}

func describeMember(name string, body []byte) string {
	if name == "debian-binary" {
		return fmt.Sprintf("version %q", strings.TrimSpace(string(body)))
	}
	return "gzip"
}

func tarGzEntries(body []byte) ([]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var out []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		kind := "-"
		if hdr.Typeflag == tar.TypeDir {
			kind = "d"
		}
		out = append(out, fmt.Sprintf("%s %04o %8d  %s", kind, hdr.Mode, hdr.Size, hdr.Name))
	}
	sort.Strings(out)
	return out, nil
}

// ----------------------------------------------------------------- 小工具 -----

func dirSizeKB(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return (total + 1023) / 1024, nil
}

func splitList(s, sep string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func humanSize(n int) string {
	switch {
	case n >= 1024*1024:
		return fmt.Sprintf("%.2f MB", float64(n)/(1024*1024))
	case n >= 1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "mkipk: "+format+"\n", a...)
	os.Exit(1)
}
