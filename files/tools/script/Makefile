# 5G 多模组管理器编译脚本（本文件住在 tools/script/）
#
# 用法：在仓库根目录跑
#   make -C files/tools/script            / build    本地编译（Windows → build/modemd.exe，增量，最快）
#   make -C files/tools/script fast                  本地编译，去掉符号表（-s -w，二进制更小）
#   make -C files/tools/script all                   本地 + 三个路由平台全编
#   make -C files/tools/script arm64|armv7|mipsle    交叉编译到 Linux 路由平台
#   make -C files/tools/script x86_64|x86            交叉编译到 x86 PC / 虚拟机（OpenWrt x86）
#   make -C files/tools/script check                 go vet + go test，然后本地编译
#   make -C files/tools/script vet|test              只做静态检查 / 只跑测试
#   make -C files/tools/script run|run-test          直接跑（生产 / 测试配置）
#   make -C files/tools/script dev                   用 run-dev.ps1 起服务（带 SAC 重试 + 端口探测）
#   make -C files/tools/script clean                 删掉编译产物
#   make -C files/tools/script help                  看这份说明
#   （也可以先 cd files/tools/script 再 make，效果一样）
#
# ⚠️ Windows 默认不带 make → 装 make（或 msys2/cygwin），也可以直接 go 命令：
#      make -C files/tools/script/            （本地编译）
#      make -C files/tools/script/ arm64      （交叉编译）
#      make -C files/tools/script/ check      （vet + 测试 + 编译）
#
# 工具链不是必须装在 PATH 上：下面的探测会自动用便携版
#   D:\Go\go_portable\go\bin\go.exe（GOROOT=D:\Go\go_portable\go）
# 并且默认 GOPROXY=off + 模块缓存 D:\Go\gopath\pkg\mod（离线环境）。

# ------------------------------------------------------------------ 目录 -------
# 本 Makefile 在 files/tools/script/ 下：所有目标都先切到仓库根目录执行
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
CD   := cd $(ROOT) &&

# ------------------------------------------------------------------ 工具链 ----
ifeq ($(OS),Windows_NT)
  # 本机 go 不在系统 PATH 上（便携版）：要换别的工具链就 make GO=go ...
  GO ?= D:/Go/go_portable/go/bin/go.exe
  EXE := .exe
else
  GO ?= go
  EXE :=
endif

# 便携版工具链兜底（PATH 里没有 go 时）
GOROOT_PORTABLE ?= D:/Go/go_portable/go
GOMODCACHE_PORTABLE ?= D:/Go/gopath/pkg/mod

export GOROOT ?= $(GOROOT_PORTABLE)
export GOMODCACHE ?= $(GOMODCACHE_PORTABLE)
export GOFLAGS ?= -mod=mod
export GOPROXY ?= off
export CGO_ENABLED = 0      # 纯 Go：交叉编译不需要额外工具链

# 所有产物统一进 build/（已在 .gitignore）
OUT      := build
BIN      := $(OUT)/modemd$(EXE)
LDFLAGS  := -s -w
# 交叉编译产物名（与 README 一致）
ARM64    := $(OUT)/modemd-arm64
ARMV7    := $(OUT)/modemd-armv7
MIPSLE   := $(OUT)/modemd-mipsle
# x86：x86_64 = PC / 虚拟机；x86 = 32 位（OpenWrt x86/generic）
X86_64   := $(OUT)/modemd-x86_64
X86      := $(OUT)/modemd-x86

.PHONY: all build fast vet test check clean help \
        arm64 armv7 mipsle x86_64 x86 build-local build-local-strip \
        build-arm64 build-armv7 build-mips \
        run run-test dev stop tidy fmt

all: build arm64 armv7 mipsle x86_64 x86

# 本地编译（增量：只重编改动的包，通常 1~3 秒）
build: build-local

fast: build-local-strip

build-local:
	@$(CD) mkdir -p $(OUT)
	$(CD) $(GO) build -o $(BIN) .
	@echo "built: $(BIN)"

build-local-strip:
	@$(CD) mkdir -p $(OUT)
	$(CD) $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) .
	@echo "built (stripped): $(BIN)"

# 路由平台：OpenWrt / 软路由常见 combo
arm64: ; @$(CD) mkdir -p $(OUT) && GOOS=linux GOARCH=arm64 $(GO) build -o $(ARM64) .
armv7: ; @$(CD) mkdir -p $(OUT) && GOOS=linux GOARCH=arm GOARM=7 $(GO) build -o $(ARMV7) .
mipsle: ; @$(CD) mkdir -p $(OUT) && GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GO) build -o $(MIPSLE) .
# x86：amd64（x86_64）与 386（SSE2，对应 OpenWrt 的 i386_pentium4）
x86_64: ; @$(CD) mkdir -p $(OUT) && GOOS=linux GOARCH=amd64 $(GO) build -o $(X86_64) .
x86:    ; @$(CD) mkdir -p $(OUT) && GOOS=linux GOARCH=386 $(GO) build -o $(X86) .

# 兼容旧名字（README / init.d 里用过）
build-arm64: arm64
build-armv7: armv7
build-mips: mipsle

# ------------------------------------------------------------------ 质量 ------
vet:
	$(CD) $(GO) vet ./...
	$(CD) $(GO) vet .

# ⚠️ 本机开了 Smart App Control 时，新编译出来的测试二进制会被随机拦截
# （报 "An Application Control policy has blocked this file"）→ 重跑几次即可。
test:
	$(CD) $(GO) test -count=1 ./...

check: vet test build

# ------------------------------------------------------------------ 运行 ------
run: ; $(CD) $(GO) run . -config config.toml
run-test: ; $(CD) $(GO) run . -config config.test.toml
# 带 SAC 重试 + 启动探测的起服务脚本（推荐：改完代码直接一条命令起来）
dev:
	$(CD) powershell -NoProfile -ExecutionPolicy Bypass -File files/tools/script/run-dev.ps1

tidy: ; $(CD) $(GO) mod tidy
fmt:  ; $(CD) gofmt -w ./module/ ./iface/ main.go web.go files/tools/
# 停服务（Windows：杀掉监听 18080 的进程与 go run 包装进程）
stop:
	$(CD) powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $$_.OwningProcess -Force }; Get-Process -Name modemd -ErrorAction SilentlyContinue | Stop-Process -Force; Remove-Item -Force modemd.pid -ErrorAction SilentlyContinue"

clean:
	$(CD) rm -f $(BIN) $(ARM64) $(ARMV7) $(MIPSLE) $(X86_64) $(X86) modemd modemd_smoke.exe
	$(CD) rm -f modemd.exe modemd-arm64 modemd-armv7 modemd-mipsle modemd-x86_64 modemd-x86

help:
	@echo "targets:"
	@echo "  build / build-local    本地编译 -> $(BIN)（增量，最快）"
	@echo "  arm64 | armv7 | mipsle 交叉编译 -> $(ARM64) / $(ARMV7) / $(MIPSLE)"
	@echo "  x86_64 | x86           交叉编译 -> $(X86_64) / $(X86)（PC / 虚拟机）"
	@echo "  fast                   本地编译 + -s -w（更小；产物统一在 $(OUT)/）"
	@echo "  all / check / vet / test / tidy / fmt / clean"
	@echo "  run | run-test | dev   直接运行 / 用 run-dev.ps1 起服务"
	@echo "  stop                   停掉正在跑的服务（释放 18080）"
	@echo ""
	@echo "需要 make（apt install make / brew install make），或直接 go build ./..."
