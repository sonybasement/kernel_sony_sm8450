LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE              := bu520x1nvx.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_PATH         := $(KERNEL_MODULES_OUT)
include $(DLKM_DIR)/Build_external_kernelmodule.mk
