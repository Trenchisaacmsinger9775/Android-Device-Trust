LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := devicecheck
LOCAL_SRC_FILES := \
    Native.cpp \
    AttestationBuilder.cpp \
    AttestationKeys.cpp \
    Compression.cpp \
    FileSignals.cpp \
    FingerprintSignals.cpp \
    FrameworkSignals.cpp \
    IntegritySignals.cpp \
    KeystoreAttestation.cpp \
    ObfuscationCipher.cpp \
    ProcSignals.cpp \
    Protocol.cpp \
    VulkanSignals.cpp
LOCAL_CPPFLAGS := -O1 -std=c++17 -Wall -Wextra -fno-rtti -fno-exceptions
LOCAL_C_INCLUDES := $(LOCAL_PATH)/Headers
LOCAL_LDLIBS := -lz -landroid -ldl -lEGL -lGLESv2

LOCAL_CPPFLAGS += -fvisibility=hidden -fvisibility-inlines-hidden -fomit-frame-pointer \
                    -ffunction-sections -fdata-sections -fno-use-cxa-atexit \
                    -fvisibility=hidden -fvisibility-inlines-hidden \
                    -fno-unwind-tables -fno-asynchronous-unwind-tables

LOCAL_LDFLAGS += -Wl,--strip-all -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,--as-needed

include $(BUILD_SHARED_LIBRARY)
