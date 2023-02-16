LOCAL_PATH := $(call my-dir)

KBUILD_OPTIONS += KBUILD_EXTRA_SYMBOLS=$(shell pwd)/$(call intermediates-dir-for,DLKM,drm-module-symvers)/Module.symvers
KBUILD_OPTIONS += TOUCH_DRIVER_SOD=$(srctree)/drivers/sony/sec_ts

include $(CLEAR_VARS)
LOCAL_MODULE              := sec_touchscreen.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_PATH         := $(KERNEL_MODULES_OUT)
LOCAL_REQUIRED_MODULES    := drm-module-symvers
LOCAL_ADDITIONAL_DEPENDENCIES := $(call intermediates-dir-for,DLKM,drm-module-symvers)/Module.symvers

include $(DLKM_DIR)/Build_external_kernelmodule.mk