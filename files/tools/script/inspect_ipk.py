# inspect_ipk.py —— 只读地看一眼 .ipk 的结构（SAC 拦住 mkipk.exe 时的临时替代）
#
# 用法： python tools\script\inspect_ipk.py build\0.2.287-1\aarch64_generic\modemd-pro_0.2.287-1_aarch64_generic.ipk
import io
import sys
import tarfile

path = sys.argv[1]
raw = open(path, "rb").read()
print("file      :", path, len(raw), "bytes")
print("magic     :", raw[:8])

if raw[:2] == b"\x1f\x8b":
    print("format    : ipkg (gzip 外层 tar)")
    outer = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
elif raw[:8] == b"!<arch>\n":
    print("format    : ar")
    raise SystemExit("ar 格式，另行处理")
else:
    print("format    : 未知")
    raise SystemExit(1)

names = outer.getnames()
print("members   :", names)
for n in names:
    f = outer.extractfile(n)
    if f is None:
        continue
    data = f.read()
    print(f"--- {n} ({len(data)} bytes) ---")
    if n.endswith("control.tar.gz") or n.endswith("data.tar.gz"):
        inner = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        for m in inner.getmembers()[:60]:
            print(f"    {m.mode:04o} {m.size:>9} {m.name}")
        if n.endswith("control.tar.gz"):
            for m in inner.getmembers():
                if m.isfile():
                    print(f"    ===== {m.name} =====")
                    print(inner.extractfile(m).read().decode("utf-8", "replace"))
    else:
        print(data.decode("utf-8", "replace"))
