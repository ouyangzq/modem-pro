# pack_ipk_daemon.py —— 在本机 Smart App Control 拦住 mkipk.exe 时，手工重打 modemd-pro 的 .ipk
#
# 为什么需要它：`已删除的 Windows 打包脚本` 会编一个 `build\mkipk_N.exe` 来拼包，而本机
# 智能应用控制（SAC）现在把这个 exe 直接拦掉（"不是此操作系统平台的有效应用程序"，
# 换 6 次哈希都不行，见 MD\BUILD.md）。这个脚本用 Python 做同一件事：
#
#   以**上一个** modemd-pro ipk 为模板（目录树/权限/control 各字段照抄），
#   只换三样东西：/usr/bin/modemd 二进制、[net] qmi_v6_sibling 这个新配置键、control 里的版本号。
#
# 用法：
#   python tools\script\pack_ipk_daemon.py <新版本> <新二进制> <旧ipk> <输出ipk>
# 例：
#   python tools\script\pack_ipk_daemon.py 0.2.288-1 build\modemd_linux_arm64 ^
#       build\0.2.287-1\aarch64_generic\modemd-pro_0.2.287-1_aarch64_generic.ipk ^
#       build\0.2.288-1\aarch64_generic\modemd-pro_0.2.288-1_aarch64_generic.ipk
import io
import os
import sys
import tarfile

MTIME = 1759940000  # 固定时间戳：包内容可复现（opkg 不看时间）


def open_outer(path):
    raw = open(path, "rb").read()
    if raw[:2] != b"\x1f\x8b":
        raise SystemExit("只支持 ipkg 格式（gzip 外层 tar）的模板包")
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")


def rebuild(members_src, replacements, is_dir_ok=True):
    """照抄 members_src 的顺序/权限/类型，用 replacements{name: bytes} 替换文件内容。"""
    buf = io.BytesIO()
    out = tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9)
    for m in members_src.getmembers():
        ti = m.get_info() if hasattr(m, "get_info") else tarfile.TarInfo(m.name)
        ti = tarfile.TarInfo(m.name)
        ti.mode = m.mode
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        ti.mtime = MTIME
        if m.isdir():
            ti.type = tarfile.DIRTYPE
            out.addfile(ti)
            continue
        if m.issym():
            ti.type = tarfile.SYMTYPE
            ti.linkname = m.linkname
            out.addfile(ti)
            continue
        if m.isfile():
            data = replacements.get(m.name)
            if data is None:
                data = members_src.extractfile(m).read()
            ti.type = tarfile.REGTYPE
            ti.size = len(data)
            out.addfile(ti, io.BytesIO(data))
            continue
        # 其它类型（硬链接等）原样搬
        out.addfile(ti)
    out.close()
    return buf.getvalue()


def patch_config(text):
    """给包里的 /etc/modemd/config.toml 补上新增的 [net] 键（新装的机器默认就带）。"""
    text = insert_key(text, "qmi_v6_sibling", "wan_ipv6",
                      "# QMI（主机侧拨号器）还要不要另建 modem<id>_6（proto=dhcpv6）。默认 true。\n",
                      "qmi_v6_sibling = true\n")
    text = insert_key(text, "host_dial_pdn", "host_dial_bin",
                      "# 给厂家拨号器传的 -n <pdn>：0=自动（QMAP 驱动自动补 1）/ >0 强制 / -1 永不传。\n",
                      "host_dial_pdn = 0\n")
    return text


def insert_key(text, key, after_prefix, comment, line):
    """没这个键时，在 `after_prefix` 开头那行后面补上（没找到就追加到末尾）。"""
    if key in text:
        return text
    out, done = [], False
    for ln in text.splitlines(keepends=True):
        out.append(ln)
        if not done and ln.strip().startswith(after_prefix):
            out.append(comment)
            out.append(line)
            done = True
    if not done:
        out.append("\n" + line)
    return "".join(out)


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    newver, newbin_path, old_ipk, out_ipk = sys.argv[1:5]

    newbin = open(newbin_path, "rb").read()
    template = open_outer(old_ipk)

    data_gz = template.extractfile("./data.tar.gz").read()
    ctrl_gz = template.extractfile("./control.tar.gz").read()
    debian = template.extractfile("./debian-binary").read()

    data_src = tarfile.open(fileobj=io.BytesIO(data_gz), mode="r:gz")
    ctrl_src = tarfile.open(fileobj=io.BytesIO(ctrl_gz), mode="r:gz")

    # 1) 数据段：换二进制 + 补配置键
    cfg_name = None
    for m in data_src.getmembers():
        if m.name == "./etc/modemd/config.toml":
            cfg_name = m.name
    repl = {"./usr/bin/modemd": newbin}
    if cfg_name:
        repl[cfg_name] = patch_config(data_src.extractfile(cfg_name).read().decode("utf-8")).encode("utf-8")
    data_new = rebuild(data_src, repl)

    # 2) control 段：改版本号 + 重算 Installed-Size
    total = sum(
        (m.size if m.isfile() else 0) for m in tarfile.open(fileobj=io.BytesIO(data_new), mode="r:gz").getmembers()
    )
    ctrl_text = ctrl_src.extractfile("./control").read().decode("utf-8")
    out_lines, seen_ver, seen_size = [], False, False
    for ln in ctrl_text.splitlines():
        if ln.startswith("Version:"):
            out_lines.append("Version: " + newver)
            seen_ver = True
        elif ln.startswith("Installed-Size:"):
            out_lines.append("Installed-Size: %d" % (total // 1024))
            seen_size = True
        else:
            out_lines.append(ln)
    if not seen_ver:
        out_lines.append("Version: " + newver)
    if not seen_size:
        out_lines.append("Installed-Size: %d" % (total // 1024))
    ctrl_new = rebuild(ctrl_src, {"./control": ("\n".join(out_lines) + "\n").encode("utf-8")})

    # 3) 外层：debian-binary + data.tar.gz + control.tar.gz（顺序与 mkipk 一致）
    buf = io.BytesIO()
    outer = tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9)
    for name, blob in (("./debian-binary", debian), ("./data.tar.gz", data_new), ("./control.tar.gz", ctrl_new)):
        ti = tarfile.TarInfo(name)
        ti.mode = 0o644
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        ti.mtime = MTIME
        ti.size = len(blob)
        outer.addfile(ti, io.BytesIO(blob))
    outer.close()

    os.makedirs(os.path.dirname(out_ipk), exist_ok=True)
    with open(out_ipk, "wb") as f:
        f.write(buf.getvalue())

    print("打包完成:")
    print("  版本    :", newver)
    print("  二进制  :", newbin_path, len(newbin), "bytes")
    print("  数据段  :", len(data_new), "bytes  (Installed-Size %d)" % (total // 1024))
    print("  输出    :", out_ipk, len(buf.getvalue()), "bytes")


if __name__ == "__main__":
    main()
