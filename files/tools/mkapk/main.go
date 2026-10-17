// mkapk - 生成 OpenWrt 25.12 起（apk 包管理器）能安装的 .apk 包。
//
//	.\go run ./tools/mkapk -Target generic          # 默认同时产出 .ipk 和 .apk
//	.\go run ./tools/mkapk -List "build\*\*.apk"    # 看/校验已有 apk 的结构
//	go test ./tools/mkapk/                                 # 自检
//
// # 为什么自己写（Windows 上没别的办法）
//
// OpenWrt 25.12 的 apk 是 apk-tools **3.0.5**（package/system/apk，commit b5a31c0）：
// 它自带的 `apk mkpkg` 只输出 v3（ADB 二进制容器：对象表 + 压缩块 + 身份摘要），
// Windows 上既没有 apk 可跑、也没法验证，硬写风险极大。
// 但同一份源码里 `extract_v2.c` 是**无条件编译**的，而 `apk_extract()` 只看开头 4 字节：
//
//	"ADB" 开头 -> v3；其它 -> v2
//
// 所以这里输出标准 v2（Alpine 用了十年的那套），OpenWrt 25.12 的 apk 一样能装。
// 下面每条约束都是从那个 commit 的源码里抠出来的（extract_v2.c / package.c / tar.c /
// io_gunzip.c / database.c / commit.c），不是猜的：
//
//  1. **v2 = 若干 gzip 成员顺序拼接**，每个成员是一个 tar：
//     ① 签名段（可选）② 控制段（.PKGINFO + 钩子脚本）③ 数据段（文件树）。
//     本工具不产出签名段：设备上要 `apk add --allow-untrusted`（自建包只能这样，
//     除非把公钥塞进设备的 /etc/apk/keys/）。
//
//  2. **.PKGINFO 里必须有 datahash**，值是**数据段那个 gzip 成员在文件里的原始字节**
//     的 sha256（十六进制）。apk 算 sha256 用到的 MPART_DATA 回调传的是**压缩输入**
//     的指针区间（io_gunzip.c），不是解压后的内容。
//     少了它：VERIFY_AND_GENERATE 分支里 `if (!has_data_checksum) return -APKE_V2PKG_FORMAT`
//     ⇒ "包格式无效"；对不上：解包时 `apk_digest_cmp` 失败 ⇒ `-APKE_V2PKG_INTEGRITY`。
//
//  3. **控制段里不能出现带 "/" 的隐藏条目**（tar 的 PAX/GNU long name 头就是
//     "./PaxHeaders/xxx" 这种）。apk 的 apk_sign_ctx_process_file 对它走 "APKv1 兼容"
//     分支，把 data_started 提前置 1，随后控制段结束时的 BOUNDARY 事件就撞上
//     `if (part == APK_MPART_BOUNDARY && sctx->data_started) return -APKE_FORMAT_INVALID`。
//     本工具全程 tar.FormatUSTAR（短名），且生成的文件名都很短，不会退化成 PAX。
//
//  4. **数据段必须是最后一个 gzip 成员**，且末尾要有连续 0 块（tar 结束标记）。
//     apk 的 tar 解析器读到**第二个**连续 0 块就退出主循环，之后有个"读完剩余结束
//     记录"的收尾循环一路读到 EOF（tar.c 末尾），只有读到 EOF 才会触发 MPART_END
//     事件，而 `data_verified` / `end_seen` 都只在那个事件里置位（否则
//     `apk_extract_v2` 末尾判 `-APKE_V2PKG_INTEGRITY`）。
//     ⇒ 数据段用标准 tar（两个 0 块）；控制段**不带**结束块（照 abuild 的
//     `abuild-tar --cut`，实测 Alpine 官方包的控制段也是无结束块）。
//     ⚠️ 但控制段**必须补齐到 512 边界**：那段收尾循环还会再读一个 512 块，读到
//     "不足 512 的残缺块"就直接走 err 分支判 `-APKE_EOF` ⇒ "unexpected end of file"
//     （2026-10-05 在 OpenWrt 25.12.5 / apk-tools 3.0.5 真机上踩到）。
//     Go 的 tar.Writer 只在下一次 WriteHeader / Close / **Flush** 时才写 512 填充，
//     所以"跳过 Close"必须换成 `tw.Flush()`，不能什么都不做。回归：
//     `TestControlHasNoEndBlocksDataHasThem`（顺带断言两段都 512 对齐）。
//
//     4b. **数据段里每个常规文件都必须带内嵌校验和**（apk-tools 3.0 起强制）：
//     fs_fsys.c 的 `apk_fs_extract()` 开头就是
//     `if (fi->digest.alg == APK_DIGEST_NONE && need_checksum(fi)) return -APKE_FORMAT_OBSOLETE;`
//     ⇒ 报 "file format is obsolete (e.g. missing embedded checksum)"，
//     并且**整包一个文件都不会落盘**（包照样记进 apk 数据库，症状是"装了但
//     /usr/bin 下什么都没有"）。目录 / 符号链接不需要（need_checksum() 对它们返回 false）。
//     载体 = PAX 扩展头 `APK-TOOLS.checksum.SHA1 = <hex sha1>`（tar.c 的
//     handle_extended_header() 解析；Alpine 官方包同样如此）。
//     ⚠️ PAX 只加在**数据段**：它的名字形如 `xxx/PaxHeaders.0/yyy`，带 "/" 又以 '.'
//     开头，落在控制段会让 apk 的 apk_sign_ctx_process_file() 走 "APKv1 兼容" 分支
//     提前置 data_started ⇒ 控制段结束的 BOUNDARY 撞 -APKE_FORMAT_INVALID。
//
//  5. **钩子脚本名是 .post-install / .pre-deinstall / .pre-upgrade …**
//     （apk_script_types[]：pre-install、post-install、pre-deinstall、post-deinstall、
//     pre-upgrade、post-upgrade、trigger），不是 ipk 的 postinst/prerm。
//     OpenWrt 的包由 buildroot（include/package-pack.mk）生成这些脚本：外壳 source
//     /lib/functions.sh、设 root/pkgname、调 default_postinst，再接上包自己的 postinst。
//     这里照抄同一套。注意 apk 会 chroot 到安装根再执行脚本，而且**不设 IPKG_INSTROOT**
//     （那套 env 是 opkg 的），所以外壳里那句 functions.sh 探测才是离线安装的开关。
//
//  6. **OpenWrt 自己的元数据文件**（apk 本体不读，但 /lib/functions.sh 读）：
//
//     /lib/apk/packages/<pkg>.list             default_postinst/prerm 靠它找 /etc/init.d/*
//     —— 少了它，装完**不会** enable/start 服务
//     /lib/apk/packages/<pkg>.conffiles        配置文件清单
//     /lib/apk/packages/<pkg>.conffiles_static 配置文件 + sha256
//     /etc/apk/protected_paths.d/<pkg>.list    apk 原生"别覆盖用户改过的配置"
//     （apk-protected_paths(5)：命中就写 .apk-new）
//     /lib/upgrade/keep.d/<pkg>                sysupgrade 刷固件时保留这些文件
//
// 这些文件由本工具打包时**合成**（不落 staging 目录），所以 .ipk 那边不受影响。
package main

import (
	"archive/tar"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
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

// 默认归档时间取固定值而不是 now()：同一个包重打两次字节一致（可复现），
// 也免得数据段的 sha256 每次都变。要真实时间就传 -mtime <unix 秒>。
const defaultMtime = int64(1700000000)

func main() {
	var (
		dataDir    = flag.String("data", "", "要打包的文件树根目录（映射到 /）")
		ctrlDir    = flag.String("control", "", "control 脚本目录（postinst/prerm/preinst/postrm），可空")
		pkg        = flag.String("package", "modemd-pro", "包名")
		version    = flag.String("version", "", "版本（原样写进 pkgver，OpenWrt 惯例 upstream-pkgrel）")
		arch       = flag.String("arch", "", "OpenWrt 架构串，如 aarch64_generic（必填）")
		maintainer = flag.String("maintainer", "modemd", "maintainer")
		desc       = flag.String("description", "", "pkgdesc")
		url        = flag.String("url", "", "url（可空：空则整条不写）")
		license    = flag.String("license", "unknown", "license 名（可空：空则写 unknown）")
		origin     = flag.String("origin", "", "origin（可空：默认等于包名）")
		depends    = flag.String("depends", "", "depend（逗号或空格分隔，可空）")
		conffiles  = flag.String("conffiles", "", "配置文件列表（逗号分隔，相对/绝对都行）")
		execs      = flag.String("exec", "", "需要 0755 的相对路径（逗号分隔）；usr/bin 与 etc/init.d 下默认就是 0755")
		out        = flag.String("out", "", "输出 .apk 路径（必填）")
		listMode   = flag.Bool("list", false, "改为解析/校验已有 .apk（后面跟文件路径）")
		deep       = flag.Bool("deep", false, "与 -list 搭配：再列出包内文件清单")
		mtimeStr   = flag.String("mtime", "", "归档时间戳（unix 秒）；默认取 SOURCE_DATE_EPOCH 或固定值")
		signKey    = flag.String("signkey", "", "RSA 私钥 PEM；给了就产出签名段（apk v2 = 签名+控制+数据），设备不必加 --allow-untrusted")
		signName   = flag.String("signname", "", "签名键名：写进 .SIGN.RSA.<name>；公钥要放到设备 /etc/apk/keys/<name>，默认 <私钥文件名>.pub")
		genKey     = flag.String("genkey", "", "生成一对 RSA-4096 密钥（<路径> 私钥 + <路径>.pub 公钥）后退出")
	)
	flag.Parse()

	if *genKey != "" {
		if err := genKeyPair(*genKey); err != nil {
			fatal("%v", err)
		}
		pub := *genKey + ".pub"
		fmt.Printf("私钥：%s（0600，别泄露）\n", *genKey)
		fmt.Printf("公钥：%s\n", pub)
		fmt.Printf("→ 把公钥放到设备的 /etc/apk/keys/%s，之后 apk add 就不需要 --allow-untrusted 了\n",
			filepath.Base(pub))
		return
	}

	if *listMode {
		files := flag.Args()
		if len(files) == 0 {
			fatal("用法：mkapk -list [-deep] <file.apk> ...")
		}
		for _, f := range files {
			if err := listAPK(f, *deep); err != nil {
				fatal("%s: %v", f, err)
			}
			fmt.Println()
		}
		return
	}

	if *out == "" {
		fatal("缺少 -out")
	}
	if *arch == "" {
		fatal("缺少 -arch")
	}
	if *version == "" {
		fatal("缺少 -version")
	}

	spec := pkgSpec{
		pkg:        *pkg,
		version:    *version,
		arch:       *arch,
		maintainer: *maintainer,
		desc:       *desc,
		url:        *url,
		license:    *license,
		origin:     *origin,
		depends:    splitList(*depends),
		conffiles:  splitList(*conffiles),
		signKey:    *signKey,
		signName:   *signName,
	}
	mt := resolveMtime(*mtimeStr)
	spec.buildTime = mt.Unix()

	res, err := buildAPK(*dataDir, *ctrlDir, spec, splitList(*execs), mt)
	if err != nil {
		fatal("%v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatal("%v", err)
	}
	if err := os.WriteFile(*out, res.blob, 0o644); err != nil {
		fatal("%v", err)
	}

	fmt.Printf("    package   : %s\n", spec.pkg)
	fmt.Printf("    version   : %s\n", spec.version)
	fmt.Printf("    arch      : %s\n", spec.arch)
	fmt.Printf("    format    : apk（apkv2：signature + control + data 三段 gzip 成员）\n")
	if res.signedName != "" {
		fmt.Printf("    signed    : .SIGN.RSA.%s\n", res.signedName)
		fmt.Printf("                （把配对公钥放到设备 /etc/apk/keys/%s，装的时候 /etc/apk/keys/ 里要有它）\n", res.signedName)
	} else {
		fmt.Printf("    signed    : 无（装了要 apk add --allow-untrusted；LuCI 后台的\"上传安装\"不会带这个参数，会失败）\n")
	}
	fmt.Printf("    files     : %d\n", res.files)
	fmt.Printf("    installed : %d KB\n", res.installedSize/1024)
	fmt.Printf("    size      : %s（signature %s + control %s + data %s）\n",
		humanSize(len(res.blob)), humanSize(res.sigLen), humanSize(res.controlLen),
		humanSize(len(res.blob)-res.sigLen-res.controlLen))
	fmt.Printf("    datahash  : %s\n", res.dataHash)
	fmt.Printf("    output    : %s\n", *out)
}

// ---------------------------------------------------------------- 数据结构 ---

// fileEntry 是"要打进 tar 的一个条目"。data 非空表示这是合成出来的文件
// （OpenWrt 的 apk 元数据那几份）；否则从 dataDir/rel 读。
type fileEntry struct {
	rel  string // 相对路径，"/" 分隔，无前导 "./"
	dir  bool
	link string // 符号链接目标
	data []byte // 合成文件内容
	mode int64
	size int64
}

// pkgSpec 是 .PKGINFO 的输入。
// installedSize / dataHash 是打包过程中算出来的（见 buildAPK）。
type pkgSpec struct {
	pkg, version, arch    string
	maintainer, desc, url string
	license, origin       string
	depends, conffiles    []string
	buildTime             int64
	installedSize         int64
	dataHash              string
	signKey, signName     string // 非空则产出签名段（见 signMember）
}

// buildResult 是打完包的结果。
type buildResult struct {
	blob          []byte
	files         int
	installedSize int64
	controlLen    int
	sigLen        int
	signedName    string
	dataHash      string
}

// buildAPK 组装一个完整的 .apk：控制段 gzip 成员 + 数据段 gzip 成员。
func buildAPK(dataDir, ctrlDir string, spec pkgSpec, execs []string, mtime time.Time) (*buildResult, error) {
	if spec.origin == "" {
		spec.origin = spec.pkg
	}
	entries, err := collect(dataDir, execs)
	if err != nil {
		return nil, err
	}

	// 合成文件：先按真实文件生成 .list，再补上缺失的目录条目
	syn := metaFiles(spec, dataDir)
	fillListFile(spec.pkg, entries, syn)
	entries, err = addSynthetic(entries, syn)
	if err != nil {
		return nil, err
	}

	var installed int64
	files := 0
	for _, e := range entries {
		if e.dir {
			continue
		}
		files++
		installed += e.size
	}
	spec.installedSize = installed

	// 数据段先打：datahash 是它 **压缩后** 的原始字节
	dataTar, err := tarBytes(entries, dataDir, mtime, true) // true = 带 tar 结束块
	if err != nil {
		return nil, err
	}
	dataMember, err := gzipBytes(dataTar, mtime)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(dataMember)

	// 控制段：.PKGINFO + 钩子脚本
	spec.dataHash = hex.EncodeToString(sum[:])
	ctrl := []fileEntry{{rel: ".PKGINFO", data: pkginfoBytes(spec), mode: 0o644}}
	ctrl = append(ctrl, scriptEntries(ctrlDir, spec.pkg)...)
	ctrlTar, err := tarBytes(ctrl, "", mtime, false) // false = 不带结束块
	if err != nil {
		return nil, err
	}
	ctrlMember, err := gzipBytes(ctrlTar, mtime)
	if err != nil {
		return nil, err
	}

	// 可选签名段。签名覆盖的是"控制段 gzip 成员的原始字节"，所以必须在
	// ctrlMember 生成之后就地把摘要算出来（见 signMember 的注释）。
	var sigMember []byte
	signedName := ""
	if spec.signKey != "" {
		signedName = spec.signName
		if signedName == "" {
			signedName = filepath.Base(spec.signKey) + ".pub"
		}
		sigMember, err = signMember(ctrlMember, spec.signKey, signedName, mtime)
		if err != nil {
			return nil, err
		}
	}

	blob := make([]byte, 0, len(sigMember)+len(ctrlMember)+len(dataMember))
	blob = append(blob, sigMember...)
	blob = append(blob, ctrlMember...)
	blob = append(blob, dataMember...)

	return &buildResult{
		blob: blob, files: files, installedSize: installed,
		controlLen: len(ctrlMember), sigLen: len(sigMember), signedName: signedName,
		dataHash: spec.dataHash,
	}, nil
}

// collect 把磁盘上的文件树收成条目表。
// 排序保证"目录一定排在它自己的子文件前面"（目录名是子文件名的真前缀）。
// ------------------------------------------------------------------ 签名 ---
//
// apk v2 = [签名段][控制段][数据段]，每段一个 gzip 成员。签名段里只有一个名为
// `.SIGN.RSA.<键名>` 的 tar 条目，内容是 RSA PKCS#1 v1.5 签名。
//
// 被签的摘要 = **控制段那个 gzip 成员的原始（压缩）字节** 的 sha1：
// apk-tools 的 io_gunzip.c 把"输入流里属于控制段的那段压缩字节"喂给 digest_ctx
// （MPART_DATA 回调传的是压缩输入缓冲里的指针区间，不是解压后的内容），
// 到控制段结束的 BOUNDARY 事件时 extract_v2.c 调 apk_verify()，
// 而 apk_verify() 走 mbedtls_pk_verify(pk, MBEDTLS_MD_SHA1, digest, sig)
// —— 正好等同于 Go 的 rsa.SignPKCS1v15(rand, priv, crypto.SHA1, sha1Sum)。
//
// ⚠️ <键名> 是设备 /etc/apk/keys/ 里的**文件名**：apk_trust_key_by_name() 用
// strcmp 精确比对，所以名字必须逐字符一致，且公钥要先放进 /etc/apk/keys/。
// 签名段本身同样"512 对齐 + 不带 tar 结束块"（与 Alpine 官方包一致）。
func signMember(ctrlMember []byte, keyPath, keyName string, mtime time.Time) ([]byte, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	priv, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(ctrlMember)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, sum[:])
	if err != nil {
		return nil, err
	}
	tar, err := tarBytes([]fileEntry{{
		rel: ".SIGN.RSA." + keyName, data: sig, mode: 0o644,
	}}, "", mtime, false)
	if err != nil {
		return nil, err
	}
	return gzipBytes(tar, mtime)
}

// parsePrivateKey 同时认 PKCS#1（RSA PRIVATE KEY）与 PKCS#8（PRIVATE KEY）。
func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("私钥不是 PEM 格式")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("私钥解析失败：%w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("私钥不是 RSA")
	}
	return rk, nil
}

// genKeyPair 生成 RSA-4096 密钥对：<path> 私钥（PKCS#1 PEM, 0600）+ <path>.pub 公钥（SPKI PEM）。
// 公钥直接就是设备 /etc/apk/keys/ 需要的那种 PEM。
func genKeyPair(path string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, privPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(path+".pub", pubPEM, 0o644)
}

func collect(dataDir string, execs []string) ([]fileEntry, error) {
	var out []fileEntry
	if dataDir != "" {
		if st, err := os.Stat(dataDir); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("数据目录不存在：%s", dataDir)
		}
		err := filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, rerr := filepath.Rel(dataDir, p)
			if rerr != nil {
				return rerr
			}
			rel = path.Clean(strings.ReplaceAll(rel, `\`, "/"))
			if rel == "." {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			e := fileEntry{rel: rel, mode: int64(info.Mode().Perm())}
			switch {
			case d.IsDir():
				e.dir = true
				e.mode = 0o755 // Windows 上目录权限没意义，统一 0755（与 ipk 一致）
			case info.Mode()&fs.ModeSymlink != 0:
				t, lerr := os.Readlink(p)
				if lerr != nil {
					return lerr
				}
				e.link = strings.ReplaceAll(t, `\`, "/")
				e.mode = 0o777
			case info.Mode().IsRegular():
				e.size = info.Size()
			default:
				fmt.Fprintf(os.Stderr, "    跳过特殊文件：%s\n", rel)
				return nil
			}
			out = append(out, e)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// 可执行位：-exec 显式给的 + 几个约定目录（与 mkipk 同一套规则）
	exec := map[string]bool{}
	for _, e := range execs {
		if n := normRel(e); n != "" {
			exec[n] = true
		}
	}
	for i := range out {
		e := &out[i]
		if e.dir || e.link != "" {
			continue
		}
		switch {
		case exec[e.rel],
			strings.HasPrefix(e.rel, "usr/bin/"),
			strings.HasPrefix(e.rel, "etc/init.d/"),
			strings.HasPrefix(e.rel, "usr/lib/modemd/"),
			strings.HasPrefix(e.rel, "lib/netifd/proto/"):
			e.mode = 0o755
		default:
			e.mode = 0o644
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// addSynthetic 把合成文件（以及缺失的父目录）并进条目表，再排序。
func addSynthetic(entries []fileEntry, syn map[string][]byte) ([]fileEntry, error) {
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.rel] = true
	}
	names := make([]string, 0, len(syn))
	for n := range syn {
		names = append(names, n)
	}
	sort.Strings(names)

	out := entries
	for _, n := range names {
		rel := normRel(n)
		if rel == "" {
			return nil, fmt.Errorf("合成文件名非法：%q", n)
		}
		if seen[rel] {
			return nil, fmt.Errorf("合成文件与数据目录里的文件重名：%s", rel)
		}
		// parentDirs 是由内到外的，反着补（外层的目录先出现）
		dirs := parentDirs(rel)
		for i := len(dirs) - 1; i >= 0; i-- {
			if d := dirs[i]; !seen[d] {
				seen[d] = true
				out = append(out, fileEntry{rel: d, dir: true, mode: 0o755})
			}
		}
		seen[rel] = true
		out = append(out, fileEntry{rel: rel, data: syn[n], mode: 0o644, size: int64(len(syn[n]))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// tarBytes 把条目表写成 tar。
//
//	dataSeg=true  → 数据段：标准 tar（两个 0 块结尾）+ 每个常规文件带
//	                `APK-TOOLS.checksum.SHA1` 的 PAX 扩展头。
//	dataSeg=false → 控制段：**不写**结束块、**不写** PAX（PAX 名形如
//	                `xxx/PaxHeaders.0/yyy`，带 "/" 且以 '.' 开头，会让 apk 的
//	                apk_sign_ctx_process_file() 走 "APKv1 兼容" 分支把 data_started
//	                提前置 1 ⇒ 控制段结束时的 BOUNDARY 撞上 -APKE_FORMAT_INVALID），
//	                但**必须**用 Flush() 补齐到 512 边界（见文件头第 4 条）。
func tarBytes(entries []fileEntry, dataDir string, mtime time.Time, dataSeg bool) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mtime = mtime.Truncate(time.Second) // USTAR 只到秒

	for _, e := range entries {
		hdr := &tar.Header{
			ModTime: mtime, Format: tar.FormatUSTAR,
			Uid: 0, Gid: 0, Uname: "root", Gname: "root",
		}
		switch {
		case e.dir:
			hdr.Typeflag = tar.TypeDir
			hdr.Name = e.rel + "/"
			hdr.Mode = orDefault(e.mode, 0o755)
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, err
			}
		case e.link != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Name = e.rel
			hdr.Linkname = e.link
			hdr.Mode = orDefault(e.mode, 0o777)
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, err
			}
		default:
			// 校验和要写进**文件头之前**的 PAX 扩展头，所以先把内容读出来算 sha1。
			content := e.data
			if content == nil {
				b, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(e.rel)))
				if err != nil {
					return nil, err
				}
				content = b
			}
			hdr.Typeflag = tar.TypeReg
			hdr.Name = e.rel
			hdr.Mode = orDefault(e.mode, 0o644)
			hdr.Size = int64(len(content))
			if dataSeg {
				// apk-tools 3.0 的 fs_fsys.c: apk_fs_extract() 对每个常规文件都要求
				// 内嵌校验和（`if (fi->digest.alg == APK_DIGEST_NONE && need_checksum(fi))
				// return -APKE_FORMAT_OBSOLETE;`），缺了报
				// "file format is obsolete (e.g. missing embedded checksum)"，
				// 且**整包一个文件都不会落盘**（包却照样记进 apk 数据库）。
				// 载体 = PAX 扩展头里的 APK-TOOLS.checksum.SHA1 =<hex sha1>
				// （tar.c 的 handle_extended_header() 解析）。
				sum := sha1.Sum(content)
				hdr.Format = tar.FormatPAX
				hdr.PAXRecords = map[string]string{
					"APK-TOOLS.checksum.SHA1": hex.EncodeToString(sum[:]),
				}
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, err
			}
			if _, err := tw.Write(content); err != nil {
				return nil, err
			}
		}
	}
	if dataSeg {
		if err := tw.Close(); err != nil { // 两个 0 块（tar 结束标记）
			return nil, err
		}
	} else {
		// 控制段：只把最后一个条目的数据补齐到 512 边界，**不写**结束块。
		// ⚠️ 这里不能"什么都不做"（不能省掉）：Go 的 tar.Writer 只在下一次
		// WriteHeader / Close / Flush 时才写补齐字节，直接 return 会让控制段
		// 长度不是 512 的整数倍。apk 的 tar 解析器（src/tar.c）读到末尾会尝试
		// 再读一个 512 块的记录，拿到"不足 512 的残缺块"后走 err 分支
		// （r >= 0 ⇒ r = -APKE_EOF）⇒ 报 "unexpected end of file"。
		// 实测：真实 Alpine v2 包的控制段也是 512 对齐、无结束块。
		if err := tw.Flush(); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// gzipBytes 压缩一个 gzip 成员。apk 的 io_gunzip.c 按成员边界发 BOUNDARY/END 事件，
// 所以"一段一个 gzip 成员"是格式硬要求，不能把两段塞进同一个 zlib 流。
func gzipBytes(b []byte, mtime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gz.Header.ModTime = mtime.Truncate(time.Second)
	if _, err := gz.Write(b); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------- .PKGINFO ---

// pkginfoBytes 生成控制段里的 .PKGINFO。
//
// ⚠️ 字段名必须**逐字**命中 apk 的 read_info_line 表
// （pkgname/pkgver/pkgdesc/url/size/license/arch/depend/install_if/provides/
// origin/maintainer/builddate/commit/provider_priority），分隔符必须是 " = "
// （apk 就是按这三个字符切的）；表外的名字 apk 直接忽略，写错了会静默丢字段。
// ⚠️ 也别用大写开头的自定义字段：v3 那条路会把未知的大写字段判成"不可安装"。
func pkginfoBytes(s pkgSpec) []byte {
	var b strings.Builder
	b.WriteString("# Generated by mkapk (OpenWrt apk, format v2)\n")
	w := func(k, v string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		fmt.Fprintf(&b, "%s = %s\n", k, strings.TrimSpace(v))
	}

	w("pkgname", s.pkg)
	w("pkgver", s.version)
	// pkgdesc 必须是单行：apk 按 \n 切行，内部换行会让后面的字段错位
	w("pkgdesc", strings.Join(strings.Fields(s.desc), " "))
	w("url", s.url)
	w("builddate", strconv.FormatInt(s.buildTime, 10))
	w("size", strconv.FormatInt(s.installedSize, 10))
	w("arch", s.arch)
	w("origin", s.origin)
	w("maintainer", s.maintainer)
	w("license", orDefaultStr(s.license, "unknown"))
	w("depend", strings.Join(s.depends, " "))
	w("datahash", s.dataHash)
	return []byte(b.String())
}

// metaFiles 生成 OpenWrt 自己那几份 apk 元数据（见文件头第 6 条）。
// .list 的内容要等真实文件收齐，所以这里先占位，由 fillListFile 填。
func metaFiles(s pkgSpec, dataDir string) map[string][]byte {
	out := map[string][]byte{"lib/apk/packages/" + s.pkg + ".list": nil}
	if len(s.conffiles) == 0 {
		return out
	}

	var cfl, sta strings.Builder
	for _, p := range s.conffiles {
		rel := normRel(p)
		if rel == "" {
			continue
		}
		abs := "/" + rel
		fmt.Fprintf(&cfl, "%s\n", abs)
		if sum := fileSHA256(filepath.Join(dataDir, filepath.FromSlash(rel))); sum != "" {
			fmt.Fprintf(&sta, "%s %s\n", abs, sum)
		}
	}
	out["lib/apk/packages/"+s.pkg+".conffiles"] = []byte(cfl.String())
	if sta.Len() > 0 {
		out["lib/apk/packages/"+s.pkg+".conffiles_static"] = []byte(sta.String())
	}

	// apk 原生保护：用户改过的配置不覆盖，改写 <file>.apk-new
	// （apk-protected_paths(5)：规则里的路径相对 root，不带前导 /）
	var pp strings.Builder
	pp.WriteString("# " + s.pkg + ": 用户改过的配置别被包覆盖（apk 会写成 .apk-new）\n")
	for _, p := range s.conffiles {
		if rel := normRel(p); rel != "" {
			fmt.Fprintf(&pp, "+%s\n", rel)
		}
	}
	out["etc/apk/protected_paths.d/"+s.pkg+".list"] = []byte(pp.String())

	// sysupgrade 保留清单（OpenWrt 给带 conffiles 的包都发这个）
	var keep strings.Builder
	for _, p := range s.conffiles {
		if rel := normRel(p); rel != "" {
			fmt.Fprintf(&keep, "/%s\n", rel)
		}
	}
	out["lib/upgrade/keep.d/"+s.pkg] = []byte(keep.String())
	return out
}

// fillListFile 用真实文件（不含合成文件）填 <pkg>.list。
// 格式照 OpenWrt：`find . -type f,l -printf "/%P\n" | sort`（只列文件，不列目录）。
// OpenWrt 的 default_postinst 就是在这份清单里 grep "^/etc/init.d/" 来决定
// enable/start 哪些服务 —— 少了它，装完服务不会自己起来。
func fillListFile(pkg string, entries []fileEntry, syn map[string][]byte) {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.dir {
			continue
		}
		names = append(names, "/"+e.rel)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s\n", n)
	}
	syn["lib/apk/packages/"+pkg+".list"] = []byte(b.String())
}

// ---------------------------------------------------------------- 钩子脚本 ---

// scriptEntries 把 ipk 那套 postinst/prerm/preinst/postrm 转成 apk 的钩子脚本。
//
// OpenWrt 的 buildroot（include/package-pack.mk）是这么生成的，这里逐条照抄：
//
//	post-install  = 外壳（source /lib/functions.sh + default_postinst）+ 包自己的 postinst 去掉 #!
//	post-upgrade  = #!/bin/sh + export PKG_UPGRADE=1 + 整份 post-install 去掉 #!
//	pre-deinstall = 外壳（default_prerm）+ 包自己的 prerm 去掉 #!
//	post-deinstall= 包自己的 postrm 原样
//	pre-install   = 外壳（只 source，不调 default_*）+ 包自己的 preinst 去掉 #!
func scriptEntries(ctrlDir, pkg string) []fileEntry {
	if ctrlDir == "" {
		return nil
	}
	if _, err := os.Stat(ctrlDir); err != nil {
		return nil
	}
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join(ctrlDir, n))
		if err != nil {
			return ""
		}
		return string(b)
	}
	stripShebang := func(s string) string {
		lines := strings.Split(s, "\n")
		if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
			lines = lines[1:]
		}
		return strings.Join(lines, "\n")
	}
	shell := func(extra, body string) string {
		var b strings.Builder
		b.WriteString("#!/bin/sh\n")
		b.WriteString("[ \"${IPKG_NO_SCRIPT}\" = \"1\" ] && exit 0\n")
		b.WriteString("[ -s \"${IPKG_INSTROOT}/lib/functions.sh\" ] || exit 0\n")
		b.WriteString(". ${IPKG_INSTROOT}/lib/functions.sh\n")
		b.WriteString("export root=\"${IPKG_INSTROOT}\"\n")
		fmt.Fprintf(&b, "export pkgname=\"%s\"\n", pkg)
		b.WriteString(extra)
		b.WriteString(body)
		return b.String()
	}

	var out []fileEntry
	if postinst := read("postinst"); postinst != "" {
		pi := shell("add_group_and_user\ndefault_postinst\n", stripShebang(postinst))
		out = append(out, fileEntry{rel: ".post-install", data: []byte(pi), mode: 0o755})
		out = append(out, fileEntry{rel: ".post-upgrade",
			data: []byte("#!/bin/sh\nexport PKG_UPGRADE=1\n" + stripShebang(pi)), mode: 0o755})
	}
	if pre := read("preinst"); pre != "" {
		out = append(out, fileEntry{rel: ".pre-install",
			data: []byte(shell("", stripShebang(pre))), mode: 0o755})
		out = append(out, fileEntry{rel: ".pre-upgrade",
			data: []byte("#!/bin/sh\nexport PKG_UPGRADE=1\n" + stripShebang(pre)), mode: 0o755})
	}
	if prerm := read("prerm"); prerm != "" {
		out = append(out, fileEntry{rel: ".pre-deinstall",
			data: []byte(shell("default_prerm\n", stripShebang(prerm))), mode: 0o755})
	}
	if postrm := read("postrm"); postrm != "" {
		out = append(out, fileEntry{rel: ".post-deinstall", data: []byte(postrm), mode: 0o755})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}

// ------------------------------------------------------------------ -list ---

// gzMember 是一个 gzip 成员及其在文件里的原始区间。
type gzMember struct {
	index    int
	start    int
	end      int
	inflated []byte
}

// splitGzipMembers 按 gzip 成员边界切分。
//
// 这里用 bytes.Reader 喂 flate 是有意的：flate 只在底层实现了 io.ByteReader 时
// 才"按需读"，否则会预读若干字节 —— 那样算出的成员边界就不准，而校验 datahash
// 恰恰需要**精确**的成员原始字节。
func splitGzipMembers(b []byte) ([]gzMember, error) {
	var out []gzMember
	off := 0
	for off < len(b) {
		if len(b)-off < 18 {
			return nil, fmt.Errorf("偏移 %d 处不足一个 gzip 成员", off)
		}
		if b[off] != 0x1f || b[off+1] != 0x8b || b[off+2] != 8 {
			hint := ""
			if off == 0 && len(b) >= 3 && string(b[:3]) == "ADB" {
				hint = " —— 这是 apk v3（ADB 容器）格式，本工具只认 v2"
			}
			return nil, fmt.Errorf("偏移 %d 处不是 gzip 头（%02x %02x %02x）%s",
				off, b[off], b[off+1], b[off+2], hint)
		}
		flg := b[off+3]
		p := off + 10
		if flg&0x04 != 0 { // FEXTRA
			if p+2 > len(b) {
				return nil, errors.New("FEXTRA 越界")
			}
			n := int(b[p]) | int(b[p+1])<<8
			p += 2 + n
		}
		for _, bit := range []byte{0x08, 0x10} { // FNAME / FCOMMENT：NUL 结尾
			if flg&bit == 0 {
				continue
			}
			for p < len(b) && b[p] != 0 {
				p++
			}
			p++
		}
		if flg&0x02 != 0 { // FHCRC
			p += 2
		}
		if p > len(b)-8 {
			return nil, errors.New("gzip 头越界")
		}

		br := bytes.NewReader(b[p:])
		fr := flate.NewReader(br)
		inflated, err := io.ReadAll(fr)
		fr.Close()
		if err != nil {
			return nil, fmt.Errorf("第 %d 个成员解压失败：%v", len(out), err)
		}
		used := len(b[p:]) - br.Len()
		end := p + used + 8 // gzip 尾部：CRC32 + ISIZE
		if end > len(b) {
			return nil, errors.New("gzip 尾部越界")
		}
		out = append(out, gzMember{index: len(out), start: off, end: end, inflated: inflated})
		off = end
	}
	return out, nil
}

func listAPK(file string, deep bool) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	fmt.Printf("=== %s\n", file)
	fmt.Printf("  size    : %d bytes\n", len(raw))
	members, err := splitGzipMembers(raw)
	if err != nil {
		return err
	}
	fmt.Printf("  members : %d 个 gzip 成员（apk v2 = 成员顺序拼接）\n", len(members))
	for _, m := range members {
		kind := "?"
		switch m.index {
		case 0:
			kind = "控制段（.PKGINFO + 钩子脚本）"
			if bytes.HasPrefix(m.inflated, []byte(".SIGN.")) {
				kind = "签名段"
			}
		case 1:
			kind = "数据段（文件树）"
		}
		fmt.Printf("    [%d] 文件偏移 %-9d 压缩 %-9d 解压 %-9d %s\n",
			m.index, m.start, m.end-m.start, len(m.inflated), kind)
	}
	if len(members) == 0 {
		return errors.New("没有任何 gzip 成员")
	}
	ctrl := members[0]
	if len(members) > 1 {
		ctrl = members[len(members)-2]
	}
	data := members[len(members)-1]

	info, err := pkginfoFromTar(ctrl.inflated)
	if err != nil {
		return err
	}
	if len(info) == 0 {
		return errors.New("控制段里没有 .PKGINFO（apk 会判 -APKE_V2PKG_FORMAT）")
	}
	fmt.Printf("  .PKGINFO :\n")
	keys := make([]string, 0, len(info))
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("      %-12s = %s\n", k, info[k])
	}

	if want := info["datahash"]; want != "" {
		sum := sha256.Sum256(raw[data.start:data.end])
		got := hex.EncodeToString(sum[:])
		if got == strings.ToLower(want) {
			fmt.Printf("  datahash : OK（数据段 gzip 成员原始字节的 sha256 一致）\n")
		} else {
			fmt.Printf("  datahash : ✗ 对不上！.PKGINFO=%s 实际=%s\n", want, got)
		}
	} else {
		fmt.Printf("  datahash : ✗ 缺失 —— apk_pkg_read 会直接判 -APKE_V2PKG_FORMAT\n")
	}

	if n := zeroTailLen(ctrl.inflated); n >= 512 {
		fmt.Printf("  warn     : 控制段结尾有 %d 字节 0 块（apk 期望没有，见 mkapk 文件头第 4 条）\n", n)
	}
	if n := zeroTailLen(data.inflated); n < 1024 {
		fmt.Printf("  warn     : 数据段结尾 0 块只有 %d 字节（apk 的 tar 收尾要求 ≥2 个连续 0 块）\n", n)
	}
	if !isUSTAR(ctrl.inflated) {
		fmt.Printf("  warn     : 控制段第一个 tar 头不是 USTAR（PAX 长名会让 apk 判 -APKE_FORMAT_INVALID）\n")
	}
	if deep {
		fmt.Printf("  数据段条目：\n")
		for _, n := range tarNames(data.inflated) {
			fmt.Printf("      %s\n", n)
		}
		fmt.Printf("  控制段条目：\n")
		for _, n := range tarNames(ctrl.inflated) {
			fmt.Printf("      %s\n", n)
		}
	}
	return nil
}

// isUSTAR 判断一段 inflate 出来的字节是否以 USTAR tar 头开头。
func isUSTAR(b []byte) bool {
	return len(b) >= 265 && string(b[257:262]) == "ustar"
}

// zeroTailLen 返回结尾连续 0 字节数。
func zeroTailLen(b []byte) int {
	n := 0
	for i := len(b) - 1; i >= 0 && b[i] == 0; i-- {
		n++
	}
	return n
}

func pkginfoFromTar(inflated []byte) (map[string]string, error) {
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(inflated))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != ".PKGINFO" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, " = ")
			if !ok {
				continue
			}
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		return out, nil
	}
}

func tarNames(inflated []byte) []string {
	var out []string
	tr := tar.NewReader(bytes.NewReader(inflated))
	for {
		hdr, err := tr.Next()
		if err != nil {
			return out
		}
		kind := "-"
		switch hdr.Typeflag {
		case tar.TypeDir:
			kind = "d"
		case tar.TypeSymlink:
			kind = "l"
		}
		out = append(out, fmt.Sprintf("%s %6d %04o %s", kind, hdr.Size, hdr.Mode&0o7777, hdr.Name))
	}
}

// ------------------------------------------------------------------ 小工具 ---

// normRel 归一化相对路径：去 ./、统一 /、剥掉前后斜杠。
// 返回空串表示这不是一个能用的相对路径（空、跳到根外、..）。
func normRel(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, `\`, "/"))
	s = strings.TrimPrefix(s, "./")
	s = strings.Trim(s, "/")
	s = path.Clean(s)
	if s == "." || s == "" || strings.HasPrefix(s, "..") {
		return ""
	}
	return s
}

// parentDirs 由内到外给出所有父目录：a/b/c -> [a/b a]。
func parentDirs(rel string) []string {
	var out []string
	for {
		i := strings.LastIndex(rel, "/")
		if i < 0 {
			return out
		}
		rel = rel[:i]
		out = append(out, rel)
	}
}

func splitList(s string) []string {
	s = strings.ReplaceAll(s, " ", ",")
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func resolveMtime(s string) time.Time {
	if s == "" {
		s = os.Getenv("SOURCE_DATE_EPOCH")
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0)
	}
	return time.Unix(defaultMtime, 0)
}

func humanSize(n int) string {
	f := float64(n)
	switch {
	case f >= 1024*1024:
		return fmt.Sprintf("%.2f MB", f/(1024*1024))
	case f >= 1024:
		return fmt.Sprintf("%.1f KB", f/1024)
	}
	return fmt.Sprintf("%d B", n)
}

func fileSHA256(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func orDefault(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}

func orDefaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "mkapk: "+format+"\n", a...)
	os.Exit(1)
}
