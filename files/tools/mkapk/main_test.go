package main

// mkapk 的自检。重点不是"代码能跑"，而是**我们生成的包会不会被真机 apk 收下**：
// 下面 TestV2StateMachine 是把 apk-tools 3.0.5 的 src/extract_v2.c 里
// apk_sign_ctx_mpart_cb() 逐行翻译过来的迷你状态机，喂我们生成的成员序列，
// 断言它最后会置上 data_verified / end_seen（apk_extract_v2 末尾就靠这两个标志
// 决定判不判 -APKE_V2PKG_FORMAT / -APKE_V2PKG_INTEGRITY）。

import (
	"archive/tar"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------ 测试脚手架 ---

// makeTree 造一棵"像真 staging 目录"的文件树，返回 (dataDir, ctrlDir)。
func makeTree(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	ctrl := filepath.Join(dir, "ctrl")
	for _, d := range []string{
		"usr/bin", "etc/init.d", "etc/modemd", "lib/netifd/proto", "usr/lib/modemd",
		"usr/share/luci/menu.d", "www/luci-static/resources/view/modemd",
	} {
		if err := os.MkdirAll(filepath.Join(data, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(ctrl, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"usr/bin/modemd":                                 "\x7fELF-fake-binary",
		"etc/init.d/modemd":                              "#!/bin/sh /etc/rc.common\nSTART=99\n",
		"etc/modemd/config.toml":                         "[net]\ndial_enabled = true\n",
		"lib/netifd/proto/quectel.sh":                    "#!/bin/sh\n",
		"usr/lib/modemd/quectel-CM":                      "\x7fELF-dialer",
		"usr/share/luci/menu.d/luci-app-modemd.json":     "{\"admin\":{}}\n",
		"www/luci-static/resources/view/modemd/index.js": "// ui\n",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(data, filepath.FromSlash(rel)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scripts := map[string]string{
		"postinst": "#!/bin/sh\n/etc/init.d/modemd enable\n/etc/init.d/modemd restart\necho 装好了\n",
		"prerm":    "#!/bin/sh\n/etc/init.d/modemd stop\n",
	}
	for n, body := range scripts {
		if err := os.WriteFile(filepath.Join(ctrl, n), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return data, ctrl
}

func testSpec() pkgSpec {
	return pkgSpec{
		pkg: "modemd-pro", version: "0.2.60-1", arch: "aarch64_generic",
		maintainer: "modemd <you@example.com>",
		desc:       "5G/LTE multi-modem manager with web UI",
		license:    "GPL-2.0-only",
		depends:    []string{"libgcc1"},
		conffiles:  []string{"etc/modemd/config.toml"},
		buildTime:  defaultMtime,
	}
}

func buildTestAPK(t *testing.T) ([]byte, map[string]string) {
	t.Helper()
	data, ctrl := makeTree(t)
	res, err := buildAPK(data, ctrl, testSpec(), []string{"usr/bin/modemd"}, time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatalf("buildAPK: %v", err)
	}
	return res.blob, tarContents(t, data)
}

// tarContents 读出数据目录里每个文件的真实内容，供后面跟包内条目比对。
func tarContents(t *testing.T, data string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.Walk(data, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, err := filepath.Rel(data, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// --------------------------------------------------------- 结构：成员与 tar ---

func TestBuildAPKTwoGzipMembers(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatalf("splitGzipMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("应该正好 2 个 gzip 成员（无签名时：控制段 + 数据段），实际 %d", len(members))
	}
	if members[0].start != 0 || members[len(members)-1].end != len(blob) {
		t.Errorf("成员区间没覆盖整个文件：%+v", members)
	}
	// 数据段必须是最后一个成员：apk 在"数据段之后又出现 BOUNDARY"时直接判格式错
	if !isUSTAR(members[1].inflated) {
		t.Errorf("第二个成员不是 tar")
	}
	if bytes.Contains(members[1].inflated, []byte(".PKGINFO")) {
		t.Errorf("数据段里不该有 .PKGINFO")
	}
	if !bytes.Contains(members[0].inflated, []byte(".PKGINFO")) {
		t.Errorf("控制段里必须有 .PKGINFO")
	}
}

// 控制段不能带 tar 结束块（abuild-tar --cut 的做法），但**必须补齐到 512 边界**：
// apk 的 tar 解析器读到最后会再尝试读一个 512 块，拿到"不足 512 的残缺块"就直接
// 报 -APKE_EOF（"unexpected end of file"）。数据段必须带结束块，同样要 512 对齐。
func TestControlHasNoEndBlocksDataHasThem(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	ctrl := members[0].inflated
	if len(ctrl)%512 != 0 {
		t.Errorf("控制段必须是 512 的整数倍，实际 %d（余 %d）；apk 读残缺块会报 EOF",
			len(ctrl), len(ctrl)%512)
	}
	if len(ctrl) >= 512 && isZeroBlock(ctrl[len(ctrl)-512:]) {
		t.Errorf("控制段最后一个 512 块是全 0：不该写 tar 结束块")
	}
	data := members[1].inflated
	if len(data)%512 != 0 {
		t.Errorf("数据段必须是 512 的整数倍，实际 %d（余 %d）", len(data), len(data)%512)
	}
	if n := zeroTailLen(data); n < 1024 {
		t.Errorf("数据段结尾至少要有 2 个连续 0 块（1024 字节），实际 %d", n)
	}
}

// 签名段：必须能用一个 tar 条目（名字 = .SIGN.RSA.<键名>）装住
// RSA PKCS#1 v1.5(SHA1(控制段原始字节))；且 tar 要 512 对齐、不带结束块
// （apk_trust_key_by_name 是文件名精确匹配，名字错了设备上就找不到公钥）。
func TestSignMemberCoversControlBlock(t *testing.T) {
	dir := t.TempDir()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "modemd-test.rsa")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	ctrl := []byte("control-member-bytes")
	member, err := signMember(ctrl, keyPath, "modemd-test.rsa.pub", time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatal(err)
	}

	members, err := splitGzipMembers(member)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("签名段应该是单个 gzip 成员，实际 %d", len(members))
	}
	if n := len(members[0].inflated); n%512 != 0 {
		t.Errorf("签名段 tar 必须 512 对齐，实际 %d", n)
	}

	var sig []byte
	tr := tar.NewReader(bytes.NewReader(members[0].inflated))
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name != ".SIGN.RSA.modemd-test.rsa.pub" {
			t.Errorf("条目名不对：%q", hdr.Name)
		}
		sig, err = io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(sig) == 0 {
		t.Fatal("签名段里没有签名条目")
	}

	sum := sha1.Sum(ctrl)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA1, sum[:], sig); err != nil {
		t.Errorf("签名必须覆盖「控制段原始字节」的 SHA1：%v", err)
	}
	// 摘要算错（比如对解压后的字节签名）必须验不过，防止以后改错。
	bad := sha1.Sum([]byte("not-the-control-member"))
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA1, bad[:], sig); err == nil {
		t.Error("签名不应该能验证其它摘要")
	}
}

// isZeroBlock 报告 b 是否是一个全 0 的 512 字节 tar 块。
func isZeroBlock(b []byte) bool {
	if len(b) != 512 {
		return false
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestDataMemberHoldsWholeTree(t *testing.T) {
	blob, want := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(members[1].inflated))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[hdr.Name] = string(body)
	}
	for rel, body := range want {
		if got[rel] != body {
			t.Errorf("数据段里 %s 内容不对（拿到 %q）", rel, got[rel])
		}
	}
	// 守护进程与 init 脚本必须带可执行位
	tr = tar.NewReader(bytes.NewReader(members[1].inflated))
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		switch hdr.Name {
		case "usr/bin/modemd", "etc/init.d/modemd", "usr/lib/modemd/quectel-CM",
			"lib/netifd/proto/quectel.sh":
			if hdr.Mode&0o111 == 0 {
				t.Errorf("%s 没有可执行位：%04o", hdr.Name, hdr.Mode)
			}
		case "etc/modemd/config.toml":
			if hdr.Mode&0o111 != 0 {
				t.Errorf("config.toml 不该有可执行位：%04o", hdr.Mode)
			}
		}
	}
}

func TestUSTARHeadersOnly(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}

	// 控制段：不能出现 "./PaxHeaders/xxx" 那种带斜杠的隐藏名 ——
	// apk 会走 "APKv1 兼容" 分支把 data_started 提前置 1，
	// 随后的 BOUNDARY 事件就被判 -APKE_FORMAT_INVALID。所以控制段一律 USTAR。
	ctrl := tar.NewReader(bytes.NewReader(members[0].inflated))
	for {
		hdr, err := ctrl.Next()
		if err != nil {
			break
		}
		if strings.HasPrefix(hdr.Name, ".") && strings.Contains(hdr.Name, "/") {
			t.Errorf("控制段条目名 %q 会触发 apk 的 APKv1 兼容分支", hdr.Name)
		}
		if hdr.Format == tar.FormatPAX || len(hdr.PAXRecords) != 0 {
			t.Errorf("控制段条目 %q 用了 PAX 头（apk 的 v2 解析器不认）", hdr.Name)
		}
	}

	// 数据段反过来：每个常规文件都必须带 APK-TOOLS.checksum.SHA1 的 PAX 记录，
	// 否则 apk 3.0 的 apk_fs_extract() 报 -APKE_FORMAT_OBSOLETE（整包不解压）。
	data := tar.NewReader(bytes.NewReader(members[1].inflated))
	nReg := 0
	for {
		hdr, err := data.Next()
		if err != nil {
			break
		}
		sum := hdr.PAXRecords["APK-TOOLS.checksum.SHA1"]
		switch hdr.Typeflag {
		case tar.TypeReg:
			if len(sum) != 40 {
				t.Errorf("数据段常规文件 %q 缺内嵌校验和（APK-TOOLS.checksum.SHA1=%q）", hdr.Name, sum)
			} else {
				nReg++
			}
		default:
			if sum != "" {
				t.Errorf("数据段 %q（typeflag=%c）不该带校验和", hdr.Name, hdr.Typeflag)
			}
		}
	}
	if nReg == 0 {
		t.Error("数据段里一个带校验和的常规文件都没有")
	}
}

// ------------------------------------------------------------- .PKGINFO -----

func TestPkginfoFields(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	info, err := pkginfoFromTar(members[0].inflated)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"pkgname": "modemd-pro", "pkgver": "0.2.60-1", "arch": "aarch64_generic",
		"depend": "libgcc1", "origin": "modemd-pro", "license": "GPL-2.0-only",
		"builddate": "1700000000",
	}
	for k, v := range want {
		if info[k] != v {
			t.Errorf(".PKGINFO %s = %q，期望 %q", k, info[k], v)
		}
	}
	// datahash 必须是 64 位十六进制（sha256），apk 拿它校验数据段
	if len(info["datahash"]) != 64 {
		t.Errorf("datahash 不是 sha256 十六进制：%q", info["datahash"])
	}
	// 只允许 apk read_info_line 表里那些名字 —— 表外的会被静默忽略
	// （v3 那条路还会把未知的大写字段判成"不可安装"）
	known := map[string]bool{
		"pkgname": true, "pkgver": true, "pkgdesc": true, "url": true, "size": true,
		"license": true, "arch": true, "depend": true, "install_if": true, "provides": true,
		"origin": true, "maintainer": true, "builddate": true, "commit": true,
		"provider_priority": true, "datahash": true,
	}
	for k := range info {
		if !known[k] {
			t.Errorf(".PKGINFO 里有 apk 不认识的字段：%q（会被静默丢掉）", k)
		}
		if k != strings.ToLower(k) {
			t.Errorf("字段名 %q 不是全小写", k)
		}
	}
	if strings.Contains(info["pkgdesc"], "\n") {
		t.Errorf("pkgdesc 必须是单行（apk 按 \\n 切行）")
	}
}

// --------------------------------------------------- OpenWrt 那几份元数据 ---

func TestOpenWrtMetadataFiles(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(members[1].inflated))
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, _ := io.ReadAll(tr)
		files[hdr.Name] = string(body)
	}

	// .list：OpenWrt 的 default_postinst 靠它 grep "^/etc/init.d/" 来 enable/start 服务
	list := files["lib/apk/packages/modemd-pro.list"]
	if !strings.Contains(list, "/etc/init.d/modemd\n") {
		t.Errorf(".list 里没有 /etc/init.d/modemd，装完服务不会自己起来：\n%s", list)
	}
	if !strings.HasPrefix(list, "/") || strings.Contains(list, "./") {
		t.Errorf(".list 每行应该是 / 开头的路径：\n%s", list)
	}
	if strings.Contains(list, "lib/apk/packages/modemd-pro.list") {
		t.Errorf(".list 不该包含它自己（照 OpenWrt 的生成顺序）")
	}

	// conffiles / conffiles_static
	if got := files["lib/apk/packages/modemd-pro.conffiles"]; got != "/etc/modemd/config.toml\n" {
		t.Errorf("conffiles 内容不对：%q", got)
	}
	sta := files["lib/apk/packages/modemd-pro.conffiles_static"]
	if !strings.HasPrefix(sta, "/etc/modemd/config.toml ") || len(strings.TrimSpace(sta)) < 70 {
		t.Errorf("conffiles_static 应该是 `<路径> <sha256>`：%q", sta)
	}

	// apk 原生保护：用户改过的 config.toml 不被覆盖，改写 .apk-new
	pp := files["etc/apk/protected_paths.d/modemd-pro.list"]
	if !strings.Contains(pp, "+etc/modemd/config.toml") {
		t.Errorf("protected_paths 规则不对：%q", pp)
	}
	// keep.d：sysupgrade 刷固件时保留配置
	if got := files["lib/upgrade/keep.d/modemd-pro"]; got != "/etc/modemd/config.toml\n" {
		t.Errorf("keep.d 内容不对：%q", got)
	}
}

// 没有 conffiles 时不该凭空造这几份文件
func TestNoConffilesNoMetadata(t *testing.T) {
	data, ctrl := makeTree(t)
	spec := testSpec()
	spec.conffiles = nil
	res, err := buildAPK(data, ctrl, spec, nil, time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatal(err)
	}
	members, err := splitGzipMembers(res.blob)
	if err != nil {
		t.Fatal(err)
	}
	names := strings.Join(tarNames(members[1].inflated), "\n")
	for _, n := range []string{"conffiles", "protected_paths", "keep.d"} {
		if strings.Contains(names, n) {
			t.Errorf("没配 conffiles 却出现了 %s：\n%s", n, names)
		}
	}
	if !strings.Contains(names, "modemd-pro.list") {
		t.Errorf(".list 无论如何都该有：\n%s", names)
	}
}

// ------------------------------------------------------------- 钩子脚本 -----

func TestScriptMapping(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	scripts := map[string]string{}
	modes := map[string]int64{}
	tr := tar.NewReader(bytes.NewReader(members[0].inflated))
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(tr)
		scripts[hdr.Name] = string(body)
		modes[hdr.Name] = hdr.Mode
	}
	// ipk 的 postinst/prerm -> apk 的 .post-install/.post-upgrade/.pre-deinstall
	for _, n := range []string{".post-install", ".post-upgrade", ".pre-deinstall"} {
		if scripts[n] == "" {
			t.Fatalf("缺脚本 %s（现有条目：%v）", n, keysOfString(scripts))
		}
		if modes[n]&0o111 == 0 {
			t.Errorf("%s 没有可执行位", n)
		}
	}
	pi := scripts[".post-install"]
	if !strings.HasPrefix(pi, "#!/bin/sh\n") {
		t.Errorf(".post-install 开头不对：%q", firstLine(pi))
	}
	// OpenWrt 的外壳：source functions.sh + default_postinst，然后才是包自己的脚本
	for _, must := range []string{"/lib/functions.sh", "default_postinst", "export pkgname=\"modemd-pro\""} {
		if !strings.Contains(pi, must) {
			t.Errorf(".post-install 缺 %q：\n%s", must, pi)
		}
	}
	if !strings.Contains(pi, "/etc/init.d/modemd enable") {
		t.Errorf(".post-install 没接上原本的 postinst 内容：\n%s", pi)
	}
	if strings.Count(pi, "#!/bin/sh") != 1 {
		t.Errorf("包自己的 postinst 那行 #! 应该被剥掉：\n%s", pi)
	}
	pu := scripts[".post-upgrade"]
	if !strings.Contains(pu, "export PKG_UPGRADE=1") || !strings.Contains(pu, "/etc/init.d/modemd restart") {
		t.Errorf(".post-upgrade 应该是 PKG_UPGRADE=1 + 整份 post-install：\n%s", pu)
	}
	pd := scripts[".pre-deinstall"]
	if !strings.Contains(pd, "default_prerm") || !strings.Contains(pd, "/etc/init.d/modemd stop") {
		t.Errorf(".pre-deinstall 不对：\n%s", pd)
	}
	// 没有 preinst/postrm 就不该有 .pre-install / .post-deinstall
	if _, ok := scripts[".pre-install"]; ok {
		t.Errorf("没有 preinst 却生成了 .pre-install")
	}
	if _, ok := scripts[".post-deinstall"]; ok {
		t.Errorf("没有 postrm 却生成了 .post-deinstall")
	}
}

func TestPostrmBecomesPostDeinstall(t *testing.T) {
	data, ctrl := makeTree(t)
	if err := os.WriteFile(filepath.Join(ctrl, "postrm"),
		[]byte("#!/bin/sh\nrm -f /tmp/luci-indexcache\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := buildAPK(data, ctrl, testSpec(), nil, time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatal(err)
	}
	members, err := splitGzipMembers(res.blob)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(members[0].inflated))
	found := false
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name != ".post-deinstall" {
			continue
		}
		body, _ := io.ReadAll(tr)
		found = true
		if !strings.HasPrefix(string(body), "#!/bin/sh") {
			t.Errorf("postrm 原样进包时该保留 shebang：%q", firstLine(string(body)))
		}
	}
	if !found {
		t.Errorf("有 postrm 却没生成 .post-deinstall")
	}
}

// --------------------------------------------------- v2 状态机（核心验证） ---

// v2Ctx 是 apk-tools 3.0.5 src/extract_v2.c 里 apk_sign_ctx_mpart_cb 的逐行翻译。
type v2Ctx struct {
	controlStarted bool
	dataStarted    bool
	hasDataHash    bool
	allowUntrusted bool

	dataHash []byte // .PKGINFO 的 datahash
	digest   hash.Hash
	identity hash.Hash

	controlVerified bool
	dataVerified    bool
	endSeen         bool
}

const (
	partData = iota
	partBoundary
	partEnd
)

func newV2Ctx(allowUntrusted bool) *v2Ctx {
	return &v2Ctx{
		allowUntrusted: allowUntrusted,
		digest:         sha1.New(), // apk 默认 SHA1，读到 datahash 时换成 SHA256
		identity:       sha1.New(),
	}
}

func (c *v2Ctx) mpart(part int, data []byte) error {
	if c.endSeen || c.dataVerified {
		return errf("format invalid：事件已经结束")
	}
	if part == partBoundary && c.dataStarted {
		return errf("format invalid：数据段之后又来了 BOUNDARY")
	}
	if part == partEnd {
		c.endSeen = true
	}
	if part == partData {
		c.digest.Write(data)
		if c.controlStarted && !c.dataStarted {
			c.identity.Write(data)
		}
		return nil
	}
	if len(data) != 0 {
		return errf("format invalid：非数据事件带了数据")
	}
	if !c.controlStarted {
		if part == partEnd {
			return errf("format invalid：还没进控制段就结束了")
		}
		c.identity.Reset()
		c.digest.Reset()
		return nil
	}
	endOfControl := !c.dataStarted
	c.dataStarted = true
	if !c.hasDataHash && endOfControl && part != partEnd {
		return nil
	}
	if c.hasDataHash && !endOfControl {
		got := c.digest.Sum(nil)
		if !bytes.Equal(got, c.dataHash) {
			return errf("integrity：datahash 对不上（包内 %s，实际 %s）",
				hex.EncodeToString(c.dataHash), hex.EncodeToString(got))
		}
		c.dataVerified = true
		if !c.allowUntrusted && !c.controlVerified {
			return errf("signature untrusted")
		}
		return nil
	}
	// 无签名（pkey == nil）+ allow-untrusted 时这里直接通过
	if !c.allowUntrusted {
		return errf("signature untrusted（这个包没签名，必须 apk add --allow-untrusted）")
	}
	c.controlVerified = true
	if !c.hasDataHash && part == partEnd {
		c.dataVerified = true
	}
	c.digest.Reset()
	return nil
}

// driveV2 模拟 apk 读包时的事件序列：
// 每个成员先来若干 MPART_DATA（按"压缩字节"喂，这正是 apk 算哈希的对象），
// 成员末尾发 BOUNDARY（最后一个成员发 END）；控制段里 tar 解析器一看到第一个条目
// 就把 controlStarted 置 1（对应 extract_v2.c 的 apk_sign_ctx_process_file）。
func driveV2(t *testing.T, raw []byte, pkgInfo map[string]string) (*v2Ctx, error) {
	t.Helper()
	members, err := splitGzipMembers(raw)
	if err != nil {
		return nil, err
	}
	c := newV2Ctx(true) // 设备上就是 apk add --allow-untrusted
	if h := pkgInfo["datahash"]; h != "" {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("datahash 不是十六进制：%w", err)
		}
		c.hasDataHash = true
		c.dataHash = b
		c.digest = sha256.New() // apk_extract_v2_control 看到 datahash 就把 alg 换成 SHA256
	}
	for i, m := range members {
		chunk := raw[m.start:m.end]
		if i == 0 {
			// 真实顺序：第一批压缩字节喂进去时 tar 解析器还没看到条目（controlStarted 还是 false）
			split := len(chunk) / 3
			if split == 0 {
				split = len(chunk)
			}
			if err := c.mpart(partData, chunk[:split]); err != nil {
				return c, err
			}
			c.controlStarted = true
			if err := c.mpart(partData, chunk[split:]); err != nil {
				return c, err
			}
		} else {
			if err := c.mpart(partData, chunk); err != nil {
				return c, err
			}
		}
		part := partBoundary
		if i == len(members)-1 {
			part = partEnd
		}
		if err := c.mpart(part, nil); err != nil {
			return c, err
		}
	}
	return c, nil
}

func TestV2StateMachine(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	info, err := pkginfoFromTar(members[0].inflated)
	if err != nil {
		t.Fatal(err)
	}
	c, err := driveV2(t, blob, info)
	if err != nil {
		t.Fatalf("模拟 apk 读包失败：%v", err)
	}
	if !c.hasDataHash {
		t.Fatalf(".PKGINFO 里没有 datahash —— 真机上 apk_pkg_read 会直接判 -APKE_V2PKG_FORMAT")
	}
	if !c.controlVerified {
		t.Errorf("controlVerified 没置位")
	}
	if !c.dataVerified {
		t.Errorf("dataVerified 没置位 —— 真机会判 -APKE_V2PKG_INTEGRITY")
	}
	if !c.endSeen {
		t.Errorf("endSeen 没置位（数据段没被读到 EOF）—— 真机会判 -APKE_V2PKG_INTEGRITY")
	}
}

// 反向验证：datahash 写错必须被这个状态机抓到（否则上面那个用例是"空转"）
func TestV2StateMachineCatchesBadHash(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	info, err := pkginfoFromTar(members[0].inflated)
	if err != nil {
		t.Fatal(err)
	}
	info["datahash"] = strings.Repeat("00", 32)
	if _, err := driveV2(t, blob, info); err == nil {
		t.Fatalf("datahash 被改成全 0 还是通过了，说明校验没生效")
	}
}

// 数据段后面再接一个 gzip 成员（= 数据段不是最后一个）必须被判格式错
func TestV2StateMachineRejectsTrailingMember(t *testing.T) {
	blob, _ := buildTestAPK(t)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	info, err := pkginfoFromTar(members[0].inflated)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := gzipBytes([]byte("junk"), time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driveV2(t, append(append([]byte{}, blob...), extra...), info); err == nil {
		t.Fatalf("数据段后面还有成员时应该报错")
	}
}

// ----------------------------------------------------------- 小工具/边界 ----

func TestSplitGzipMembersThreeParts(t *testing.T) {
	// 造一个"带签名段"的三段包（Alpine 官方包就是三段），确认切分点精确
	mk := func(body string) []byte {
		b, err := gzipBytes([]byte(body), time.Unix(defaultMtime, 0))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b, c := mk("sig"), mk("ctl"), mk("data")
	blob := append(append(append([]byte{}, a...), b...), c...)
	members, err := splitGzipMembers(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 {
		t.Fatalf("应该切出 3 段，实际 %d", len(members))
	}
	wantStarts := []int{0, len(a), len(a) + len(b)}
	for i, m := range members {
		if m.start != wantStarts[i] {
			t.Errorf("第 %d 段起点 %d，期望 %d", i, m.start, wantStarts[i])
		}
	}
	if members[2].end != len(blob) {
		t.Errorf("最后一段没覆盖到文件末尾")
	}
}

func TestNormRel(t *testing.T) {
	cases := map[string]string{
		"etc/modemd/config.toml":  "etc/modemd/config.toml",
		"/etc/modemd/config.toml": "etc/modemd/config.toml",
		"./etc/a":                 "etc/a",
		`etc\a`:                   "etc/a",
		"..":                      "",
		"../../etc/passwd":        "",
		"/":                       "",
		"etc/a/../b":              "etc/b",
	}
	for in, want := range cases {
		if got := normRel(in); got != want {
			t.Errorf("normRel(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestParentDirs(t *testing.T) {
	if got := strings.Join(parentDirs("a/b/c"), ","); got != "a/b,a" {
		t.Errorf("parentDirs = %q，期望 \"a/b,a\"", got)
	}
}

// 重名保护：合成文件撞上真文件时必须报错，而不是静默覆盖
func TestSyntheticCollision(t *testing.T) {
	data, ctrl := makeTree(t)
	if err := os.MkdirAll(filepath.Join(data, "lib", "apk", "packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "lib", "apk", "packages", "modemd-pro.list"),
		[]byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAPK(data, ctrl, testSpec(), nil, time.Unix(defaultMtime, 0)); err == nil {
		t.Fatalf("合成文件与目录里的文件重名时应该报错")
	}
}

// 同样一棵树打两次必须字节一致（可复现构建；数据段哈希不会每次乱跳）
func TestReproducible(t *testing.T) {
	data, ctrl := makeTree(t)
	a, err := buildAPK(data, ctrl, testSpec(), nil, time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildAPK(data, ctrl, testSpec(), nil, time.Unix(defaultMtime, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.blob, b.blob) {
		t.Errorf("两次构建结果不一致（%d vs %d 字节）", len(a.blob), len(b.blob))
	}
}

// ------------------------------------------------------------ 小助手 ------

func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }

func keysOfString(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
