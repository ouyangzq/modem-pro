#
# SIMCom 的 qmi_wwan（qmi_wwan_simcom）—— OpenWrt 内核包
#
# ⚠️ 这份 Makefile 是**照同级厂商包补出来的**（对照 fibocom_QMI_WWAN / meig_QMI_WWAN /
#    quectel_QMI_WWAN 的 Makefile）：SIMCom 给的 rar 里只有 `qmi_wwan_simcom.c`，
#    没有包 Makefile / Kconfig。字段是照抄那几份的写法，**没有在目标固件上编译过** ——
#    内核模块必须对着同版本内核树编才有效（vermagic），见 README「三个坑」。
#
# 包名 qmi_wwan_simcom 与源文件名一致，所以 .ko 就是 qmi_wwan_simcom.ko。
#
include $(TOPDIR)/rules.mk

PKG_NAME:=qmi_wwan_simcom
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/qmi_wwan_simcom
  SUBMENU:=WWAN Support
  TITLE:=SIMCom Linux USB QMI WWAN Driver
  DEPENDS:=+kmod-usb-net +kmod-usb-wdm
  FILES:=$(PKG_BUILD_DIR)/qmi_wwan_simcom.ko
  AUTOLOAD:=$(call AutoLoad,82,qmi_wwan_simcom)
endef

define KernelPackage/qmi_wwan_simcom/description
  SIMCom (QMI) WWAN driver - mainline qmi_wwan plus SIMCom's own usbnet bind/tx/rx fixups
  (SIM8200: control+data in one function, line state; SIM7600: RAW_IP only).
endef

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	CXXFLAGS="$(TARGET_CXXFLAGS)" \
	M="$(PKG_BUILD_DIR)" \
	$(EXTRA_KCONFIG)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,qmi_wwan_simcom))
