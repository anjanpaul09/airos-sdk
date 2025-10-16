##############################################################################
#
# IOCTL 80211 abstraction layer - lib
#
##############################################################################
UNIT_NAME := ioctl80211

#
# Static library type
#
UNIT_TYPE := LIB

#
# IOCTL files
#
ifeq ($(CONFIG_PLATFORM_QCA_QSDK110),y)
UNIT_SRC += ioctl80211_11ax.c
UNIT_SRC += ioctl80211_survey_11ax.c
UNIT_SRC += ioctl80211_scan_11ax.c
UNIT_SRC += ioctl80211_client_11ax.c
UNIT_SRC += ioctl80211_radio_11ax.c
UNIT_SRC += ioctl80211_device_11ax.c
ifeq ($(CONFIG_SM_CAPACITY_QUEUE_STATS),y)
UNIT_SRC += ioctl80211_capacity_11ax.c
endif
else
UNIT_SRC += ioctl80211.c
UNIT_SRC += ioctl80211_survey.c
UNIT_SRC += ioctl80211_scan.c
UNIT_SRC += ioctl80211_client.c
UNIT_SRC += ioctl80211_radio.c
UNIT_SRC += ioctl80211_device.c
ifeq ($(CONFIG_SM_CAPACITY_QUEUE_STATS),y)
UNIT_SRC += ioctl80211_capacity.c
endif
endif

UNIT_SRC += ioctl80211_priv.c

UNIT_CFLAGS := -I$(UNIT_PATH)/inc
UNIT_CFLAGS += -Isrc/lib/datapipeline/inc

ifeq ($(CONFIG_PLATFORM_QCA_QSDK110),y)
ifeq ($(CONF_OPENSYNC_NL_SUPPORT),y)
UNIT_CFLAGS += -DOPENSYNC_NL_SUPPORT
endif
endif

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)

UNIT_DEPS := src/lib/ds
UNIT_DEPS := src/lib/common
UNIT_DEPS += src/lib/evsched
UNIT_DEPS += src/lib/schema
UNIT_DEPS += src/lib/const
UNIT_DEPS += src/lib/protobuf

