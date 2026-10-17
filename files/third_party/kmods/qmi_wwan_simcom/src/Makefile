# Kbuild：OpenWrt 的 KernelPackage 会 `make -C $(LINUX_DIR) M=<build_dir> modules`，
# 这里只要告诉它编哪个模块即可（.ko 名字来自源文件，包 Makefile 的 FILES 与之一致）。
#
# ⚠️ 照同级厂商包（fibocom_QMI_WWAN/src/Makefile 等）补的最小版本：那几份还带了
#    `default/install/clean` 目标（给人手工在设备上 `make` 用的），OpenWrt 打包用不到，
#    这里就不放了。**没有在目标固件上编译过** —— 见上一层 README「三个坑」。
obj-m += qmi_wwan_simcom.o
