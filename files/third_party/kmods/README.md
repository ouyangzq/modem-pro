# 厂商内核驱动（kmod）：来源、用途与怎么编

## 这是哪来的

用户提供的 `5G-Modem-Support` 源码集里的**内核驱动包**，原样拷过来（保留各自的
`Makefile`（OpenWrt 包 Makefile）、`src/Makefile` 与 `Kconfig`）。
它们都是 OpenWrt **feed 风格**的包目录 —— 每个子目录里有自己的 `Makefile`，
所以这个 `files/third_party/kmods/` 目录本身就能当一个 feed 用（见下面「怎么编」）。

| 目录 | 包名 | 版本 | 是什么 |
| --- | --- | --- | --- |
| `quectel_QMI_WWAN` | `qmi_wwan_q` | 3.0 | 移远分支的 `qmi_wwan`（主线 `qmi_wwan` 的加强版：更多 PID、`rawip`/`add_mux`/QMAP 支持），另带 `rmnet_nss.c` |
| `meig_QMI_WWAN` | `qmi_wwan_m` | 1.0 | 美格分支的 `qmi_wwan`（从主线 fork，265 条设备条目，覆盖到很老的 3G/4G 卡） |
| `fibocom_QMI_WWAN` | `qmi_wwan_f` | — | 广和通分支的 `qmi_wwan`（FG150/FM150/FG101/NL668 等，带"固定 rawip 接口号"表） |
| `quectel_Gobinet` | `gobinet` | 1.6.3 | GobiNet 驱动（走 QMI **控制口 + 数据口**的另一套模型，`GobiNetCM.c` 那条路的拨号器要用它） |
| `quectel_MHI` | `pcie_mhi` | 1.3.8 | 移远 PCIe 模组的 MHI 驱动（M.2 PCIe 形态的 5G 模组） |
| `fibocom_MHI` | `pcie_mhi_fb` | 3.2 | 广和通 PCIe 模组的 MHI 驱动 |
| `quectel_SRPD_PCIE` | `sprd_pcie` | 1.6 | 展锐平台 PCIe 驱动（含 `sipa` / `sipc` / `mcd` / `power_manager` 子模块） |
| `qmi_wwan_simcom` | `qmi_wwan_simcom` | 1.0（包 Makefile 是本项目补的） | SIMCom 的 `qmi_wwan`：主线 `qmi_wwan` + SIMCom 自己的 usbnet `bind/tx_fixup/rx_fixup`（SIM8200 把控制口与数据口合在一个 function 上、要处理 line state；SIM7600 **只支持 RAW_IP 模式**）。来源：SIMCom `SIM8200_OS_Driver/…/qmi_wwan_simcom.rar`。⚠️ 厂商原包只有 `.c`，`Makefile` / `src/Makefile` 是**本项目照同级厂商包补的**（未编译验证） |
| `ndisc` | `ndisc6` | 1.0.2 | ⚠️ **不是内核模块**：IPv6 邻居发现工具（`ndisc6`/`rdisc6` 等），带两个 patch（`100-favor_bsd`、`110-strverscmp`）。模组当 IPv6 网关、要排 IPv6 邻居表时才用得上 |

## ⚠️ 这些**不随** `modemd-pro` 的 ipk 发布

内核模块必须与目标固件的**内核版本 + 配置**严格匹配（`vermagic`），而且要在 Linux 上对着
那一份内核树编；本项目的构建机是 Windows，`modemd-pro` 的 ipk 是**纯用户态**包
（daemon + 4 个拨号器 + netifd 协议脚本 + LuCI 页面）。所以：

- **固件自带的 `qmi_wwan` 能抓住模组**（绝大多数情况）→ 什么都不用装，modemd 直接用它，
  只是要自己把 `raw_ip` 切成 `Y`（modemd 已经做了，见 README「QMI 模式」）；
- **固件不认模组 / 你要 GobiNet、PCIe MHI** → 才需要编这里的驱动，且**必须**用与路由器
  同版本内核的 SDK（或厂商 SDK）编。

## 怎么编（OpenWrt SDK / 固件源码树）

```sh
# ① 按包拷进 SDK 的 package/ 下
cp -r files/third_party/kmods/quectel_QMI_WWAN /path/to/sdk/package/
cd /path/to/sdk && make package/quectel_QMI_WWAN/compile V=s
# 产物：bin/packages/<arch>/base/qmi_wwan_q_*.ipk（或 build_dir 下的 .ko）

# ② 或者把本目录整成一个 feed（每个子目录都是一个包）
echo "src-link vendor /path/to/5g-modem-manager/files/third_party/kmods" >> feeds.conf
./scripts/feeds update vendor && ./scripts/feeds install -a -p vendor
make menuconfig   # Kernel modules -> ...
make package/qmi_wwan_q/compile V=s
```

⚠️ 三个坑：

1. **vermagic 不匹配 = 装了也 insmod 不进去**（`invalid module format`）。必须用目标固件自己的
   内核树；跨固件版本抄 `.ko` 基本没用。
2. **别让两份 `qmi_wwan` 抢同一张卡**：厂商分支（`qmi_wwan_q/_m/_f`）与内核自带的 `qmi_wwan`
   都绑同一个 VID/PID 时，谁先绑上看加载顺序。装了厂商分支就要 `blacklist qmi_wwan`（或反过来），
   否则会出现"控制口被另一份驱动占住"这类怪现象。
3. **`ndisc` 是用户态工具**，直接 `make package/ndisc6/compile` 就能出 ipk（不需要内核树）。

## 顺手抄走的东西：权威 VID/PID

这些驱动的 `products[]` / `id_table` 是**厂商认证过**的设备身份表，比到处搜 PID 靠谱得多。
`module/kernel/usbhotplug.go` 里的几个新条目就是从这儿抄的：

| 厂商 | 抄自 | 用到的条目 |
| --- | --- | --- |
| 美格 | `meig_QMI_WWAN/src/qmi_wwan_m.c` | `2dee:4d22`（SRM815）、`05c6:f601`（SLM750） |
| 广和通 | `fibocom_QMI_WWAN/src/qmi_wwan_f.c` | `2cb7:0104/0109/0113`（FG150/FM150/FG101）、`1508:1000/1001`（NL668）、`05c6:9025`（NL668） |
| 移远 | `quectel_QMI_WWAN/src/qmi_wwan_q.c` | `2c7c:0121/0191/0195/030b/0435/0700`（EC21/EG91/EG95/EG065k/AG35/BG95） |
| 芯讯通 | `qmi_wwan_simcom/src/qmi_wwan_simcom.c` | `05c6:90db`（SIM8200 在 "QMI 模式" 下会枚举成这个 —— 与 `1e0e:9001` 是同一张卡的不同枚举方式，两条都已进 `usbhotplug.go`） |

接入新厂商的完整清单见 README「新增厂商」。
