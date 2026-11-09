INSTALL_TARGET_PROCESSES = Preferences

include ../../build-support/build-lanes.mk
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ShadowSettings

ShadowSettings_FILES = $(wildcard *.m)
ShadowSettings_FRAMEWORKS = Foundation
ShadowSettings_EXTRA_FRAMEWORKS = AltList
ShadowSettings_PRIVATE_FRAMEWORKS = Preferences
ShadowSettings_INSTALL_PATH = /Library/PreferenceBundles
ShadowSettings_CFLAGS = -fobjc-arc -I../Shadow.framework/Headers
ifeq ($(SHADOW_LANE),rootless)
override ARCHS := $(call lane_field,$(SHADOW_LANE),UI_ARCHS)
ShadowSettings_FILES += ../Shadow.framework/Settings.m ../Shadow.framework/SettingsMigration.m ../Shadow.framework/HookConfiguration.m
ShadowSettings_CFLAGS += -DSHADOW_SETTINGS_EMBEDDED
else
ShadowSettings_EXTRA_FRAMEWORKS += Shadow
endif
ifeq ($(SHADOW_LANE),rootful-legacy)
ShadowSettings_CFLAGS += -Wno-unguarded-availability-new
endif
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_CFLAGS += -DSHADOW_ROOTHIDE
endif
# iOS 18 libobjc authenticates ObjC class references when it maps an arm64e
# image; a plain BIND in the chained-fixup table makes readClass trap before
# +load. Only clang 21 emits the -fptrauth-objc-* qualified relocations that
# the linker turns into BIND_AUTH, so new-ABI lanes compile this bundle with a
# dedicated toolchain (provisioned via $THEOS/bin/setup-modern-toolchain.sh).
# arm64 ignores the flags; the identifiers below only affect ad-hoc signing.
ifneq ($(SHADOW_LANE),)
ifeq ($(call lane_field,$(SHADOW_LANE),ABI),new)
UI_TOOLCHAIN := $(THEOS)/toolchain/modern21/linux/iphone
override TARGET_CC := $(UI_TOOLCHAIN)/bin/clang
override TARGET_CXX := $(UI_TOOLCHAIN)/bin/clang++
ShadowSettings_CFLAGS += -fptrauth-objc-isa -fptrauth-objc-class-ro -fptrauth-objc-interface-sel
ShadowSettings_CODESIGN_FLAGS = -S -IShadowSettings
endif
endif

ShadowSettings_LDFLAGS = -rpath /Library/Frameworks -rpath /var/jb/Library/Frameworks -rpath /usr/lib -rpath /var/jb/usr/lib
ShadowSettings_LDFLAGS += -F../
ifeq ($(THEOS_PACKAGE_SCHEME),roothide)
ShadowSettings_LDFLAGS += -lroothide
# bundle.mk stamps an absolute LC_ID_DYLIB ($(THEOS_PACKAGE_INSTALL_PREFIX)
# is empty under roothide); roothide requires loader-relative ids and
# check-binary-compat enforces @loader_path/.jbroot/. Instance LDFLAGS come
# after internal ones, so this override wins.
ShadowSettings_LDFLAGS += -Wl,-install_name,@loader_path/.jbroot$(ShadowSettings_INSTALL_PATH)/ShadowSettings
endif

include $(THEOS_MAKE_PATH)/bundle.mk
