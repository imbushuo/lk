LOCAL_DIR := $(GET_LOCAL_DIR)

INCLUDES += -I$(LOCAL_DIR)/include -I$(LK_TOP_DIR)/platform/msm_shared
INCLUDES += -I$(LK_TOP_DIR)/dev/gcdb/display -I$(LK_TOP_DIR)/dev/gcdb/display/include

PLATFORM := msm8974

MEMBASE := 0x0FF00000 # SDRAM Modified
# MEMBASE := 0x0F900000 # SDRAM
MEMSIZE := 0x00100000 # 1MB

BASE_ADDR        := 0x00000

TAGS_ADDR        := BASE_ADDR+0x00000100
KERNEL_ADDR      := BASE_ADDR+0x00008000
RAMDISK_ADDR     := BASE_ADDR+0x01000000
SCRATCH_ADDR     := 0x11000000

# We want it to be a littler higher, at least away from the first 128MB
UEFI_FB_BASE := 0x10400000
UEFI_FB_SIZE := 0x00800000
UEFI_FB_HORZ := 1080
UEFI_FB_VERT := 1920

DEFINES += DISPLAY_SPLASH_SCREEN=1
DEFINES += DISPLAY_TYPE_MIPI=1
DEFINES += DISPLAY_TYPE_DSI6G=1
DEFINES += WITH_DEBUG_UART=1
DEFINES += CHAINLOADED_UEFI=1
DEFINES += WITH_DEBUG_FBCON=1

MODULES += \
	dev/keys \
	dev/pmic/pm8x41 \
	dev/gcdb/display \
	dev/pmic/pmi8994 \
    lib/ptable \
    lib/libfdt

DEFINES += \
	MEMSIZE=$(MEMSIZE) \
	MEMBASE=$(MEMBASE) \
	BASE_ADDR=$(BASE_ADDR) \
	TAGS_ADDR=$(TAGS_ADDR) \
	KERNEL_ADDR=$(KERNEL_ADDR) \
	RAMDISK_ADDR=$(RAMDISK_ADDR) \
	SCRATCH_ADDR=$(SCRATCH_ADDR) \
	UEFI_FB_BASE=$(UEFI_FB_BASE) \
	UEFI_FB_SIZE=$(UEFI_FB_SIZE) \
	UEFI_FB_VERT=$(UEFI_FB_VERT) \
	UEFI_FB_HORZ=$(UEFI_FB_HORZ)

OBJS += \
    $(LOCAL_DIR)/init.o \
    $(LOCAL_DIR)/meminfo.o \
    $(LOCAL_DIR)/target_display.o \
    $(LOCAL_DIR)/oem_panel.o
