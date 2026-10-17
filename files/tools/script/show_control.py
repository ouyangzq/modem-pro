# show_control.py —— 只打印一个 ipk 里的 control（写 UTF-8 文件，避开控制台编码）
import io
import sys
import tarfile

path = sys.argv[1]
out = sys.argv[2]
raw = open(path, "rb").read()
outer = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
ctrl = None
for n in outer.getnames():
    if n.endswith("control.tar.gz"):
        inner = tarfile.open(fileobj=io.BytesIO(outer.extractfile(n).read()), mode="r:gz")
        for m in inner.getmembers():
            if m.name.endswith("/control") or m.name == "./control":
                ctrl = inner.extractfile(m).read().decode("utf-8", "replace")
            elif m.isfile():
                print("control member:", m.name, m.size)
text = ctrl or "(no control found)"
open(out, "w", encoding="utf-8").write(text)
print("wrote", out)
