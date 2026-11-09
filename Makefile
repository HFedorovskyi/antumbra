include build-support/build-lanes.mk

# Package metadata + maintainer scripts live under packaging/layout/ (kept out
# of the project root). Local to this Makefile: the subprojects keep their own
# conventional layout/ dirs, so this must never be exported to them.
THEOS_LAYOUT_DIR_NAME := packaging/layout

include $(THEOS)/makefiles/common.mk
SUBPROJECTS += src/Shadow.framework
SUBPROJECTS += src/Shadow.dylib
SUBPROJECTS += src/ShadowCore.dylib
SUBPROJECTS += src/ShadowSettings.bundle
SUBPROJECTS += src/shdw
include $(THEOS_MAKE_PATH)/aggregate.mk

# The rootless scheme stages the whole layout/ under /var/jb. Select the
# matching ruleset-watcher plist after staging, before packaging.
# The embedded-settings bundle compiles ../Shadow.framework/*.m, so theos
# drops its intermediates into the framework obj dir, which is then
# rsynced into staging. Strip build junk from the payload.
before-package::
	$(ECHO_NOTHING)find "$(THEOS_STAGING_DIR)" -type f \( -name '*.o' -o -name '*.Td' \) -delete$(ECHO_END)
# Layout files copied in from a host checkout keep that host's uid/gid; a
# payload must not ship them.
	$(ECHO_NOTHING)find "$(THEOS_STAGING_DIR)" -exec chown 0:0 {} +$(ECHO_END)
ifeq ($(THEOS_PACKAGE_SCHEME),rootless)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.watcher.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.blacklistd.plist"$(ECHO_END)
	$(ECHO_NOTHING)mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.watcher.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.watcher.plist"$(ECHO_END)
	$(ECHO_NOTHING)mv "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.blacklistd.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.blacklistd.plist"$(ECHO_END)
else
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.watcher.rootless.plist" "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.blacklistd.rootless.plist"$(ECHO_END)
endif
ifeq ($(SHADOW_LANE),rootful-legacy)
	$(ECHO_NOTHING)rm -f "$(THEOS_STAGING_DIR)/Library/LaunchDaemons/me.fedorovskyi.antumbra.blacklistd.plist"$(ECHO_END)
else
	$(ECHO_NOTHING)mkdir -p "$(THEOS_STAGING_DIR)/usr/local/bin"$(ECHO_END)
	$(ECHO_NOTHING)$(THEOS)/toolchain/linux/iphone/bin/clang -target arm64-apple-ios14.0 -isysroot "$(THEOS)/sdks/iPhoneOS$(word 3,$(subst :, ,$(TARGET))).sdk" -fobjc-arc -O2 -Wno-deprecated-declarations -framework Foundation -framework Security -framework IOKit -o "$(THEOS_STAGING_DIR)/usr/local/bin/shdwbl" "$(THEOS_PROJECT_DIR)/src/shdwbl/shdwbl.m"$(ECHO_END)
	$(ECHO_NOTHING)$(THEOS)/toolchain/linux/iphone/bin/ldid -S "$(THEOS_STAGING_DIR)/usr/local/bin/shdwbl"$(ECHO_END)
endif
# BSD-3-Clause: a binary distribution must carry the notice, conditions and
# disclaimer, so the license ships inside the payload as well as at the root
# of the source tree.
	$(ECHO_NOTHING)mkdir -p "$(THEOS_STAGING_DIR)/usr/share/doc/me.fedorovskyi.antumbra"$(ECHO_END)
	$(ECHO_NOTHING)cat "$(THEOS_PROJECT_DIR)/LICENSE" "$(THEOS_PROJECT_DIR)/NOTICE" > "$(THEOS_STAGING_DIR)/usr/share/doc/me.fedorovskyi.antumbra/copyright"$(ECHO_END)
