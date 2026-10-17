package luciauth

// LuCI 登录同步（OpenWrt）：设备中心 / API 要求先登录**路由器管理员账号**。
//
// ⚠️⚠️ 为什么不是"直接拿 LuCI 的 cookie"（我一开始就是这么设计的，真机实测被推翻）：
// 本机（OpenWrt 25.12 / LuCI ucode）发的会话 cookie 是
//     set-cookie: sysauth_http=<sid>; path=/cgi-bin/luci/; SameSite=strict; HttpOnly
// **path 限定在 `/cgi-bin/luci/`** ⇒ 浏览器根本不会把它带到 `:8899/api/...`（路径不匹配），
// SameSite=strict + HttpOnly 更是雪上加霜。所以"同一个 cookie"在浏览器上走不通。
//
// ✅ 实际做法（同账号、同会话，仍然是"同步登录"）：
//   1. 前端未登录时弹一个登录框（默认用户名 root），用户拿**路由器管理员密码**登录；
//   2. modemd 不自己验密码，而是用 `ubus call session login` 让 **rpcd** 去验，拿到一个
//      **真实的 rpcd 会话 ID**（LuCI 登录走的就是同一条路）；
//   3. 这个 ID 写进自己的 cookie `modemd_sess`（HttpOnly、SameSite=Lax、Path=/）；
//   4. 每个请求拿它去问 rpcd：`ubus call session get '{"ubus_rpc_session":"<sid>"}'`
//      —— 活跃就放行，返回 "Not found"/空 values 就 401。
//   ⇒ 与 LuCI **同一个账号密码**；在 LuCI 里点退出（`session destroy`）、或会话超时，
//     我们这边也会立刻失效（最多少看一眼缓存的 15 秒）—— 这就是"同步"。
//
// 另外：`sysauth_http`/`sysauth_https`（LuCI 自己的 cookie）**仍然认**：
//   · 命令行 / 脚本显式带 `sysauth_*` 时能直接用（不用先登录）；
//   · 将来 LuCI 若把 cookie 的 path 改回 `/`，浏览器就又能自动带上了。
//
// 默认**开**（`[ui] require_luci_login`）：用户 2026-10-06 定的口径 ——「默认打开，没有配置也是打开」。
// 配置文件里**没有这一行**（从旧版升级上来的机器就是这么回事）也算开；
// 只有显式写 `require_luci_login = false`（LuCI「服务控制」页那个开关写的就是它）才是关。
// 打开后仍有三道"别把自己锁死"的保险：
//   · 127.0.0.1 免登录（本机脚本 / 排障 / 打包自检）；
//   · 这台机器上找不到 ubus（非 OpenWrt，比如 Windows 上跑 modemd）⇒ 整体不启用；
//   · ubus 调不起来（超时 / rpcd 挂了）⇒ 放行并留日志，只有"rpcd 明确回答没这个会话"
//     才拒绝（见 luciSessionValidQuery 的注释）。
//
// 放行不等于没风险：/api/version、/api/login、/api/logout 与静态页面（/、/mini、/layouts/*）
// 永远放行 —— 要能打开页面才谈得上登录；版本号不敏感（排障用）；
// 登录接口本身当然不能要会话（它就是发会话的），靠限流挡暴力猜密码。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"modemd/module/config"
	"modemd/module/httpx"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// luciSessionOKTTL 验证通过的缓存时长。为什么不每个请求都查：
	// /api 请求很密（推送 1 秒一次、页面一开就是十几条），fork 一次 ubus 几毫秒，
	// 而 15 秒足够短 —— 用户在路由器上登出后最多 15 秒这边就跟着要求登录。
	luciSessionOKTTL = 15 * time.Second
	// luciSessionBadTTL 验证失败的缓存时长（更短：用户刚登录完就能立刻放行，
	// 同时挡住"拿着无效 cookie 猛刷 /api"把 ubus 打爆）。
	luciSessionBadTTL = 5 * time.Second
	// luciSessionMaxCache 缓存条目上限，超过就整表清空（防恶意塞满内存）
	luciSessionMaxCache = 512
	// luciUbusTimeout 单次 ubus 调用超时
	luciUbusTimeout = 3 * time.Second
	// luciSessionIDMinLen / MaxLen 会话 ID 的合理长度（LuCI 的 sid 是 32 位十六进制，
	// 放宽一点；上下界主要是别把超长垃圾传给 ubus 当参数）
	luciSessionIDMinLen = 16
	luciSessionIDMaxLen = 128
	// LuciCookieHTTP / LuciCookieHTTPS LuCI 自己的会话 cookie 名。
	// ⚠️ 它们的 path 是 `/cgi-bin/luci/`（真机实测）⇒ **浏览器不会带到 :8899**；
	// 仍然认它们是为了兼容命令行/脚本显式传 cookie，以及将来 LuCI 改回 path=/ 的情况。
	LuciCookieHTTP  = "sysauth_http"
	LuciCookieHTTPS = "sysauth_https"
	LuciCookieOld   = "sysauth"
	// ModemdSessCookie 我们自己发的会话 cookie（**主力**）：值是 `ubus call session login`
	// 换来的**真实 rpcd 会话 ID** —— 与 LuCI 同一套账号密码、同一个会话表。
	ModemdSessCookie = "modemd_sess"
	// ModemdWidgetCookie 给**嵌在 LuCI 页面里的**悬浮小窗用的会话 cookie。
	// 嵌页那边从 LuCI 只读端点拿到当前会话 ID（它自己的 sysauth_* 是 HttpOnly，JS 读不到），
	// 再写成本 cookie（path=/，host 级 ⇒ 同主机的 :8899 也会带上）。
	ModemdWidgetCookie = "modemd_widget"
	// LuciSIDParam / LuciSIDHeader 嵌页那边把会话 ID **拼在 URL 参数 / 请求头**里传进来
	// （按用户 2026-10-06 的要求："在嵌入页面拼装传入参数，go 接收到这些参数来实现免登"）。
	// ⚠️ 不传就还是普通登录模式（前端弹登录条）。
	LuciSIDParam  = "luci_sid"
	LuciSIDHeader = "X-Luci-Sid"
)

// luciSessionEntry 单个会话 ID 的验证结果缓存
type luciSessionEntry struct {
	ok bool
	at time.Time
}

var (
	luciSessionMu    sync.Mutex
	luciSessionCache = map[string]luciSessionEntry{}
	// LuciUBusOnce/LuciUBusPath 缓存 ubus 的路径（LookPath 只做一次；空串 = 没有）
	LuciUBusOnce sync.Once
	LuciUBusPath string
	// LuciUbusLookPath 实际去找 ubus 的函数（抽成变量：单测要假装“这台机器上有 ubus”，
	// 否则在 Windows 上跑测试时中间件永远是关闭的，测不到闸门）
	LuciUbusLookPath = realLuciUbusLookPath
	// LuciSessionCheck 真正去问 rpcd 的函数（单独抽出来：单测替换它，不依赖真设备）
	LuciSessionCheck = luciSessionQuery
)

// realLuciUbusLookPath 找 ubus 可执行文件：先 PATH，再几个 OpenWrt 常见路径。
func realLuciUbusLookPath() string {
	if p, err := exec.LookPath("ubus"); err == nil {
		return p
	}
	for _, p := range []string{"/bin/ubus", "/sbin/ubus", "/usr/bin/ubus", "/usr/sbin/ubus"} {
		if fi, err := exec.LookPath(p); err == nil {
			return fi
		}
	}
	return ""
}

// LuciAuthEnabled 当前是否启用「跟随 LuCI 登录」：
// 配置里开着（**没写这一行也算开着**，见 config.go 的 Load）+ 这台机器上确实有 ubus
// （非 OpenWrt / Windows 上跑 modemd 就没有 ⇒ 不启用）。
// 要关：LuCI「服务控制」页的开关，或把 `[ui] require_luci_login = false` 写进 config.toml。
func LuciAuthEnabled() bool {
	if !config.Cfg.UI.RequireLuciLogin {
		return false
	}
	return luciUbusBinary() != ""
}

// luciUbusBinary 找 ubus 可执行文件（只找一次）。
func luciUbusBinary() string {
	LuciUBusOnce.Do(func() { LuciUBusPath = LuciUbusLookPath() })
	return LuciUBusPath
}

// LuciSessionIDs 从请求里取出所有候选会话 ID，只留格式合法的。
// 来源（按顺序）：
//  1. `luci_sid` 查询参数 / `X-Luci-Sid` 请求头 —— **嵌在 LuCI 页面里的小窗**就是这么传的
//     （用户要求的方式：嵌页拿到 LuCI 会话 ID，拼参传给 modemd ⇒ 免登）；
//  2. `modemd_widget` cookie —— 同一套东西的 cookie 形式（写进 path=/ 后 :8899 也会带上）；
//  3. `modemd_sess` —— 设备中心自己登录拿到的会话（主力）；
//  4. `sysauth_http`/`sysauth_https`/`sysauth` —— LuCI 自己的 cookie（path 限制导致浏览器
//     带不到 :8899，但命令行/脚本会带，且将来 LuCI 改 path 后能直接用）。
func LuciSessionIDs(r *http.Request) []string {
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if LuciSessionIDLooksValid(v) {
			out = append(out, v)
		}
	}
	add(r.URL.Query().Get(LuciSIDParam))
	add(r.Header.Get(LuciSIDHeader))
	for _, name := range []string{ModemdWidgetCookie, ModemdSessCookie, LuciCookieHTTPS, LuciCookieHTTP, LuciCookieOld} {
		c, err := r.Cookie(name)
		if err != nil || c == nil {
			continue
		}
		add(c.Value)
	}
	return out
}

// LuciSessionIDLooksValid 会话 ID 的形状检查：长度合理 + 只含 URL 安全字符。
// 不合法的一律当"没有会话"处理（也顺带避免把奇怪字符串当 ubus 参数）。
func LuciSessionIDLooksValid(sid string) bool {
	if len(sid) < luciSessionIDMinLen || len(sid) > luciSessionIDMaxLen {
		return false
	}
	for i := 0; i < len(sid); i++ {
		c := sid[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// ResetLuciSessionCache 清空会话校验缓存（单测用；将来要加“立刻重新校验”的运维入口也走它）。
func ResetLuciSessionCache() {
	luciSessionMu.Lock()
	luciSessionCache = map[string]luciSessionEntry{}
	luciSessionMu.Unlock()
}

// LuciSessionValid 校验会话 ID 是否还有效（带短缓存）。
func LuciSessionValid(sid string) bool {
	now := time.Now()
	luciSessionMu.Lock()
	e, hit := luciSessionCache[sid]
	luciSessionMu.Unlock()
	if hit {
		ttl := luciSessionBadTTL
		if e.ok {
			ttl = luciSessionOKTTL
		}
		if now.Sub(e.at) < ttl {
			return e.ok
		}
	}

	ok := LuciSessionCheck(sid)

	luciSessionMu.Lock()
	if len(luciSessionCache) >= luciSessionMaxCache {
		luciSessionCache = map[string]luciSessionEntry{}
	}
	luciSessionCache[sid] = luciSessionEntry{ok: ok, at: time.Now()}
	luciSessionMu.Unlock()
	return ok
}

// luciSessionQuery 真的去问 rpcd：`ubus call session get '{"ubus_rpc_session":"<sid>"}'`
//
// 三种结果的处理方式（安全性与"别把自己锁死"之间的取舍）：
//   - 命令正常返回 + 有 username      → 有效
//   - 命令正常返回 + values 空        → 无效（这就是"没登录 / 会话过期了"）
//   - 命令根本没跑起来（超时、没权限）→ **放行** + 留日志：rpcd 出问题时不能连设备中心
//     都进不去；这种"放行"只发生在 ubus 自身不可用时。
//   - 命令跑了但非零退出 → 按无效处理（rpcd 明确说不行）+ 把 stderr 写日志便于排查。
func luciSessionQuery(sid string) bool {
	bin := luciUbusBinary()
	if bin == "" {
		return true // 没有 ubus：整体不启用（LuciAuthEnabled 已经挡了，这里是兜底）
	}
	ctx, cancel := context.WithTimeout(context.Background(), luciUbusTimeout)
	defer cancel()
	// 参数用 %q 包成 JSON 字符串（sid 已做形状检查，双保险）
	arg := fmt.Sprintf(`{"ubus_rpc_session":%q}`, sid)
	cmd := exec.CommandContext(ctx, bin, "call", "session", "get", arg)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			config.Logger.Warn("luci session check timed out, allowing request",
				zap.Duration("timeout", luciUbusTimeout))
			return true
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			config.Logger.Warn("luci session check: ubus returned error, treating session as invalid",
				zap.String("stderr", strings.TrimSpace(string(ee.Stderr))), zap.Error(err))
			return false
		}
		config.Logger.Warn("luci session check unavailable, allowing request", zap.Error(err))
		return true
	}
	ok, known := LuciSessionGetOK(out, time.Now())
	if !known {
		// 输出解析不了 = rpcd 的字段名变了（版本差异）。这时候宁可放行 + 大声留日志，
		// 也不要因为猜错字段把用户锁在自己的设备外面。
		config.Logger.Warn("luci session check: unparsable output, allowing request",
			zap.String("out", strings.TrimSpace(string(out))))
		return true
	}
	return ok
}

// LuciSessionGetOK 解析 `ubus call session get` 的应答。
// 返回 (是否有效, 是否解析成功)：第二个值是 false 表示"看不懂这份输出"，调用方自己决定。
// 单独抽成纯函数是为了能单测（真设备不在手边也能验收判定逻辑）。
func LuciSessionGetOK(out []byte, now time.Time) (bool, bool) {
	var resp struct {
		Values  map[string]any `json:"values"`
		Expires int64          `json:"expires"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return false, false
	}
	user, _ := resp.Values["username"].(string)
	if strings.TrimSpace(user) == "" {
		// values 里没有 username：这个会话不存在 / 已过期（rpcd 对未知 sid 就回空 values）
		return false, true
	}
	// 带 expires（秒级时间戳）时再对一次表：有些版本 get 不会主动清过期会话
	if resp.Expires > 0 && resp.Expires <= now.Unix() {
		return false, true
	}
	return true, true
}

// LuciAuthAllowPath 这些路径永远放行（不参与会话校验）。
//
//   - 静态页面与资源：要能打开页面，才谈得上在页面上提示"请先登录路由器"；
//   - /api/version：只有一个版本号，未登录也能看（排障时最想知道的就是"装的哪个版本"）；
//   - /api/login、/api/logout：一个是"发会话"的、一个是"销会话"的，都不能要求先有会话
//     （登录接口靠限流挡暴力猜密码，见 ApiLogin）；/api/session 只报"你登录了没"，也放行；
//   - 其它 /api/* 与 /ws：一律要会话（/ws 是推送通道，不放行就不会变成后门）。
func LuciAuthAllowPath(p string) bool {
	if p == "/ws" {
		return false
	}
	if strings.HasPrefix(p, "/api/") {
		switch p {
		case "/api/version", "/api/login", "/api/logout", "/api/session":
			return true
		}
		return false
	}
	return true
}

// LuciAuthLoopback 是不是本机请求（127.0.0.1 / ::1）—— 本机免登录。
//
// 为什么要有：设备上的脚本、故障排查、打包后的自检都从本机打接口；
// 而且能从本机发起请求的前提是"已经在设备上"，不存在网络侧越权。
// ⚠️ 只看 r.RemoteAddr（内核给的，伪造不了）；**故意不看** X-Forwarded-For 之类
// 可伪造的请求头。
func LuciAuthLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "::1" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// LuciLoginURL 给前端"去登录"用的地址：同主机（去掉端口）的 LuCI 登录页。
func LuciLoginURL(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return "/cgi-bin/luci/"
	}
	return "http://" + host + "/cgi-bin/luci/"
}

// writeNeedLogin 未登录时的统一应答：HTTP 401 + need_login/login_url。
// 用 HTTP 401（而不是 200 里塞 code）是为了让 curl / 脚本也能一眼看出被挡了；
// 码值不复用短信那套 code=401，避免设备中心把短信页的"锁屏"弹出来。
func writeNeedLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// 未登录的应答不要被中间缓存起来（否则登录后还一直吃 401）
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":       -1,
		"data":       nil,
		"msg":        "需要登录：请用路由器管理员账号（与 LuCI 同一个密码）",
		"need_login": true,
		// login_url 是"去路由器管理页"的兜底入口（前端的登录框是主力，见 web/index.html）
		"login_url": LuciLoginURL(r),
	})
}

// WrapLuciAuth 把「跟随 LuCI 登录」套在所有路由外面。
//
// 不启用时是纯粹的一层透传（零开销）；启用后按上面的规则放行/拒绝。
func WrapLuciAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !LuciAuthEnabled() || LuciAuthAllowPath(r.URL.Path) || LuciAuthLoopback(r) {
			next.ServeHTTP(w, r)
			return
		}
		// 只要**任意一个**候选 cookie 有效就放行（同机可能同时存在 http/https 两份）
		for _, sid := range LuciSessionIDs(r) {
			if LuciSessionValid(sid) {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeNeedLogin(w, r)
	})
}

// ====================== 登录 / 退出（与路由器同一套账号）======================
//
// 为什么 modemd 自己发会话：LuCI 的 cookie 带 `path=/cgi-bin/luci/`（真机实测），
// 浏览器不会把它带到 :8899 —— 所以由我们用**路由器管理员账号密码**向 rpcd 要一个会话
// （`session login`，LuCI 登录走的就是同一条路），再把会话 ID 写进自己的 cookie。
// 这样：同一个密码、同一个会话表；在 LuCI 里退出或会话超时，这边立刻失效。

const (
	// ubusAnonymousSID 匿名会话 ID（ubus 约定的全 0；"用这个 sid 去调"= 建一个匿名会话）
	ubusAnonymousSID = "00000000000000000000000000000000"
	// luciLoginTimeoutSec 登录后会话有效期（秒）。12 小时够用；rpcd 自己的超时也会生效
	// （取两者中更早到期的那个），所以不会因为这里写得长而永不过期。
	luciLoginTimeoutSec = 12 * 3600
	// LuciLoginMaxTries / luciLoginWindow 登录限流：同一个 IP 在一个窗口内最多试几次。
	// `session login` 自己不限流，而登录接口必须放行（它就是发会话的）⇒ 这里兜住暴力猜密码。
	LuciLoginMaxTries = 5
	luciLoginWindow   = 60 * time.Second
	// DefaultUbusHTTP ubus 的 HTTP JSON-RPC 端点（uhttpd 的 `ubus_prefix`，默认 /ubus）。
	// 登录/退出走它而不是 `ubus` 命令行：**密码/会话 ID 走请求体，不会出现在 ps 里**。
	DefaultUbusHTTP = "http://127.0.0.1/ubus"
)

var (
	// RpcdLogin / RpcdDestroy 让 rpcd 验密码 / 销毁会话（单测替换它们，不依赖真设备）
	RpcdLogin   = rpcdSessionLogin
	RpcdDestroy = rpcdSessionDestroy
	// ubusHTTPDoer 发 /ubus 请求用的 HTTP 客户端（单测可替换）
	ubusHTTPDoer = func() *http.Client { return &http.Client{Timeout: luciUbusTimeout} }
	// loginTries 登录尝试记录（按来源 IP）
	loginTries = struct {
		mu   sync.Mutex
		hits map[string][]time.Time
		now  func() time.Time
	}{hits: map[string][]time.Time{}, now: time.Now}
)

// ubusHTTPURL 取 /ubus 端点地址（配置可覆盖：uhttpd 换过端口/前缀时用）
func ubusHTTPURL() string {
	if u := strings.TrimSpace(config.Cfg.UI.UbusHTTP); u != "" {
		return u
	}
	return DefaultUbusHTTP
}

// clientIP 请求来源 IP。⚠️ 只看 RemoteAddr（内核给的，伪造不了），**不看**
// X-Forwarded-For 这类可伪造的头 —— 否则限流会被伪造头绕过。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.Trim(host, "[]")
}

// loginAllowed 记一次登录尝试并判断是否放行；返回（是否放行, 还要等多久）
func loginAllowed(ip string) (bool, time.Duration) {
	now := loginTries.now()
	loginTries.mu.Lock()
	defer loginTries.mu.Unlock()
	keep := loginTries.hits[ip][:0]
	for _, t := range loginTries.hits[ip] {
		if now.Sub(t) < luciLoginWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) >= LuciLoginMaxTries {
		wait := luciLoginWindow - now.Sub(keep[0])
		loginTries.hits[ip] = keep
		return false, wait
	}
	loginTries.hits[ip] = append(keep, now)
	// 防内存被一堆伪造来源撑满：记录太多时只保留当前这个 IP
	if len(loginTries.hits) > 256 {
		loginTries.hits = map[string][]time.Time{ip: loginTries.hits[ip]}
	}
	return true, 0
}

// ResetLoginLimiter 清空登录尝试记录（单测用）
func ResetLoginLimiter() {
	loginTries.mu.Lock()
	loginTries.hits = map[string][]time.Time{}
	loginTries.mu.Unlock()
}

// forgetLuciSession 把某个会话从校验缓存里删掉（退出登录时用，别让它还能用 15 秒）
func forgetLuciSession(sid string) {
	luciSessionMu.Lock()
	delete(luciSessionCache, sid)
	luciSessionMu.Unlock()
}

// setSessCookie / clearSessCookie 我们的会话 cookie（HttpOnly：JS 读不到，防 XSS 偷会话）
func setSessCookie(w http.ResponseWriter, r *http.Request, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name: ModemdSessCookie, Value: sid, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: luciLoginTimeoutSec,
		Secure: r.TLS != nil,
	})
}

func clearSessCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: ModemdSessCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
	})
}

// ubusRPCCall 调一次 ubus 的 HTTP JSON-RPC（LuCI 前端调 rpcd 用的就是这套）。
// 返回（应答数据, 错误）。ubus 状态码非 0 会变成错误（6 = 权限/密码不对）。
func ubusRPCCall(obj, method string, args map[string]any) (json.RawMessage, error) {
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "call",
		"params": []any{ubusAnonymousSID, obj, method, args},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, ubusHTTPURL(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ubusHTTPDoer().Do(req)
	if err != nil {
		return nil, fmt.Errorf("连不上 ubus（%s 打不通，uhttpd 没跑或端口不是 80？）：%w", ubusHTTPURL(), err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseUbusRPCBody(body)
}

// ParseUbusRPCBody 解析 JSON-RPC 应答。单独抽出来是为了能单测（真机不在手边也能验）。
//
// 成功的形状（真机实测）：
//
//	{"jsonrpc":"2.0","id":1,"result":[0,{"ubus_rpc_session":"…","timeout":3600,…}]}
//	错密码：              {"jsonrpc":"2.0","id":1,"result":[6]}
func ParseUbusRPCBody(body []byte) (json.RawMessage, error) {
	var resp struct {
		Result []json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("ubus 应答不是 JSON：%s", truncateForLog(body, 120))
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("ubus 报错 %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("ubus 应答缺少 result：%s", truncateForLog(body, 120))
	}
	var status int
	if err := json.Unmarshal(resp.Result[0], &status); err != nil {
		return nil, fmt.Errorf("ubus 应答状态码格式不对：%s", truncateForLog(body, 120))
	}
	if status != 0 {
		return nil, ubusStatusError(status)
	}
	if len(resp.Result) < 2 {
		return nil, nil // 状态 0 但没有数据（比如 destroy 成功）
	}
	return resp.Result[1], nil
}

// ubusStatusError 把 ubus 状态码翻成人话（只翻我们真正会遇到的几个）
func ubusStatusError(status int) error {
	switch status {
	case 4:
		return errors.New("会话不存在或已过期")
	case 5:
		return errors.New("路由器不支持这个操作")
	case 6:
		// 登录时 = 用户名或密码不对
		return errors.New("用户名或密码不对")
	default:
		return fmt.Errorf("ubus 状态码 %d", status)
	}
}

// truncateForLog 日志里只留一小段应答，避免把敏感/超长内容写进日志
func truncateForLog(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ParseSessionLogin 解析 `session login` 的应答数据，取出会话 ID（纯函数，便于单测）
func ParseSessionLogin(data json.RawMessage) (string, bool) {
	var resp struct {
		Session string `json:"ubus_rpc_session"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", false
	}
	s := strings.TrimSpace(resp.Session)
	if !LuciSessionIDLooksValid(s) || strings.Trim(s, "0") == "" {
		return "", false
	}
	return s, true
}

// rpcdSessionLogin 用路由器管理员账号密码换一个 rpcd 会话（= LuCI 登录）。
func rpcdSessionLogin(username, password string, timeoutSec int) (string, error) {
	data, err := ubusRPCCall("session", "login", map[string]any{
		"username": username, "password": password, "timeout": timeoutSec,
	})
	if err != nil {
		return "", err
	}
	sid, ok := ParseSessionLogin(data)
	if !ok {
		return "", fmt.Errorf("rpcd 没有返回会话 ID：%s", truncateForLog(data, 120))
	}
	return sid, nil
}

// rpcdSessionDestroy 销毁会话（与路由器管理页同步退出）。
//
// ⚠️ 为什么不用 `/ubus`（和登录一样走 HTTP）：**`session.destroy` 被 rpcd 的 ACL 挡住**，
// 真机两种 caller 都试过，都是 `{"error":{"code":-32002,"message":"Access denied"}}`：
//
//	· 匿名会话（全 0）当 caller；
//	· **会话自己**当 caller。
//
// 所以销毁只能走 `ubus` 命令行（root，不受 rpcd 那套 ACL 限制，真机实测 exit=0 且随后
// `session get` 回 "Not found"）。代价是 sid 会短暂出现在 argv 里 —— 它是"这次就要销毁的东西"，
// 不像密码那样可复用；密码一律只走 /ubus 请求体（不进 ps）。
func rpcdSessionDestroy(sid string) error {
	bin := luciUbusBinary()
	if bin == "" {
		return errors.New("这台机器上没有 ubus（非 OpenWrt）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), luciUbusTimeout)
	defer cancel()
	arg := fmt.Sprintf(`{"ubus_rpc_session":%q}`, sid)
	if out, err := exec.CommandContext(ctx, bin, "call", "session", "destroy", arg).CombinedOutput(); err != nil {
		return fmt.Errorf("%v（%s）", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApiLogin POST /api/login {"username":"root","password":"…"}
//
// 未启用登录校验（[ui] require_luci_login=false）时它只回一句"不需要登录"，
// 免得有人以为这里能改密码。
func ApiLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !LuciAuthEnabled() {
			httpx.WriteJSON(w, 0, map[string]any{"auth": false}, "未启用登录校验，无需登录")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := httpx.DecodeBody(r, &req); err != nil {
			httpx.WriteJSON(w, -1, nil, err.Error())
			return
		}
		user := strings.TrimSpace(req.Username)
		if user == "" {
			user = "root"
		}
		ip := clientIP(r)
		if ok, wait := loginAllowed(ip); !ok {
			config.Logger.Warn("login rate limited", zap.String("ip", ip), zap.String("user", user))
			httpx.WriteJSON(w, -1, map[string]any{"retry_after": int(wait.Seconds()) + 1},
				fmt.Sprintf("尝试太频繁，请等 %d 秒后再试", int(wait.Seconds())+1))
			return
		}
		sid, err := RpcdLogin(user, req.Password, luciLoginTimeoutSec)
		if err != nil {
			// 失败必须留痕（含来源 IP），但**不告诉客户端**是账号错还是密码错
			config.Logger.Warn("login failed", zap.String("ip", ip), zap.String("user", user), zap.Error(err))
			httpx.WriteJSON(w, -1, nil, "登录失败："+err.Error())
			return
		}
		setSessCookie(w, r, sid)
		config.Logger.Info("login ok", zap.String("ip", ip), zap.String("user", user))
		httpx.WriteJSON(w, 0, map[string]any{"username": user}, "登录成功")
	}
}

// ApiLogout POST /api/logout —— 顺手把 rpcd 会话也销毁（与路由器管理页同步退出）。
//
// 放在放行名单里：会话已经过期时也要能把 cookie 清掉（HttpOnly，JS 自己删不了）。
func ApiLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sid string
		if c, err := r.Cookie(ModemdSessCookie); err == nil && c != nil {
			sid = strings.TrimSpace(c.Value)
		}
		clearSessCookie(w, r)
		if sid != "" && LuciSessionIDLooksValid(sid) {
			forgetLuciSession(sid)
			if err := RpcdDestroy(sid); err != nil {
				config.Logger.Warn("logout: destroy rpcd session failed",
					zap.String("ip", clientIP(r)), zap.Error(err))
			}
		}
		httpx.WriteJSON(w, 0, nil, "已退出登录")
	}
}

// ApiSession GET /api/session —— 当前登录状态（前端用它决定要不要弹登录框）
func ApiSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !LuciAuthEnabled() {
			httpx.WriteJSON(w, 0, map[string]any{"auth": false, "logged_in": true}, "未启用登录校验")
			return
		}
		for _, sid := range LuciSessionIDs(r) {
			if LuciSessionValid(sid) {
				httpx.WriteJSON(w, 0, map[string]any{"auth": true, "logged_in": true}, "已登录")
				return
			}
		}
		if LuciAuthLoopback(r) {
			httpx.WriteJSON(w, 0, map[string]any{"auth": true, "logged_in": true, "local": true},
				"本机免登录")
			return
		}
		httpx.WriteJSON(w, 0, map[string]any{"auth": true, "logged_in": false}, "未登录")
	}
}
