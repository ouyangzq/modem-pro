package main

// mkipk 的自检：重点是 **control.tar.gz 里必须有 ./conffiles**。
//
// 背景（2026-10-01 真机定位的坑）：以前 -conffiles 参数被收下却没写进包，
// opkg 于是不把 /etc/modemd/config.toml 当配置文件 —— 每次 opkg install 都
// 用包里的默认值覆盖设备上的，微信机器人凭据 / 推送开关全丢（"每次升级都要
// 重新扫码登录"就是这么来的）。下面的用例守住这个行为。

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConffilesBytes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"相对路径补成绝对", []string{"etc/modemd/config.toml"}, "/etc/modemd/config.toml\n"},
		{"已带斜杠不改", []string{"/etc/modemd/config.toml"}, "/etc/modemd/config.toml\n"},
		{"点斜杠也会归一", []string{"./etc/modemd/config.toml"}, "/etc/modemd/config.toml\n"},
		{"去重", []string{"etc/a", "/etc/a", " etc/a "}, "/etc/a\n"},
		{"多个排序", []string{"etc/z", "etc/a"}, "/etc/a\n/etc/z\n"},
		{"空列表不产出", []string{"", "   "}, ""},
		{"不许跳出根目录", []string{"../../etc/passwd", "..", "/"}, ""},
	}
	for _, c := range cases {
		got := string(conffilesBytes(c.in))
		if got != c.want {
			t.Errorf("%s: conffilesBytes(%q) = %q，期望 %q", c.name, c.in, got, c.want)
		}
	}
}

func TestPackControlTGZWritesConffiles(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	ctrlDir := filepath.Join(dir, "ctrl")
	if err := os.MkdirAll(filepath.Join(dataDir, "etc", "modemd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 打在包里的默认配置（升级时不允许覆盖用户那份）
	if err := os.WriteFile(filepath.Join(dataDir, "etc", "modemd", "config.toml"), []byte("enabled = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// control 目录里的脚本要原样进包
	if err := os.WriteFile(filepath.Join(ctrlDir, "postinst"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	spec := controlSpec{
		pkg: "modemd", version: "0.1.0-1", arch: "all", section: "net", priority: "optional",
		maintainer: "t <t@example.com>", desc: "test", dataDir: dataDir,
		conffiles: []string{"etc/modemd/config.toml"},
	}
	tgz, err := packControlTGZ(ctrlDir, spec, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("packControlTGZ: %v", err)
	}

	got := map[string]string{}
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		got[strings.TrimPrefix(hdr.Name, "./")] = string(body)
	}

	if got["conffiles"] != "/etc/modemd/config.toml\n" {
		t.Errorf("./conffiles 内容不对：%q（整包条目：%v）", got["conffiles"], keysOf(got))
	}
	if _, ok := got["postinst"]; !ok {
		t.Errorf("control 目录里的 postinst 应原样打进包：%v", keysOf(got))
	}
	if !strings.Contains(got["control"], "Package: modemd") {
		t.Errorf("control 内容不对：%q", got["control"])
	}
}

// 没写 -conffiles 时不要凭空造一个空文件（空列表 ⇒ 不产出）
func TestPackControlTGZOmitsEmptyConffiles(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tgz, err := packControlTGZ("", controlSpec{
		pkg: "p", version: "1", arch: "all", section: "net", priority: "optional",
		maintainer: "t", desc: "d", dataDir: dataDir,
	}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("packControlTGZ: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimPrefix(hdr.Name, "./") == "conffiles" {
			t.Error("没有 conffiles 时不该出现这个条目")
		}
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
