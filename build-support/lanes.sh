# Shadow's build-lane matrix. The fields every project targeting a lane must
# agree on -- ARCHS, TARGET, SCHEME, DEPLOY, DEPLOY_ARM64E, ABI -- come from
# $THEOS/bin/lane.sh so Shadow and HookKit cannot drift apart. Only Shadow's own
# packaging identity and firmware limits are defined here.
#
# Sourced by .github/scripts/build-deps.sh and build.sh; the root Makefile reads
# the same fields via $(shell). Consumers must read these fields rather than
# duplicate package limits.

. "${THEOS:?THEOS must point to Theos}/bin/lane.sh"

shadow_lane_field() { # <lane> <field>
    # Shared fields are Theos's; only Shadow-specific ones are answered here.
    case "$2" in
    FLOOR|CEILING|PACKAGE|PACKAGE_ARCH|ARCHS|UI_ARCHS) ;;
    *) theos_lane_field "$1" "$2"; return ;;
    esac
    case "$1:$2" in
    # The rootless payload ships thin arm64 on purpose: the Linux ld64 emits
    # chained fixups as DYLD_CHAINED_PTR_ARM64E (format 1), which iOS 18's newer
    # ABI rejects, so an arm64e slice traps instead of loading. A thin arm64
    # payload makes arm64e processes skip injection cleanly. UI bundles still
    # take the arm64e slice through UI_ARCHS, but only when compiled with
    # -fptrauth-objc-* so their class references are authenticated binds --
    # see the toolchain override in src/ShadowSettings.bundle/Makefile.
    rootless:ARCHS)               echo "arm64" ;;
    rootless:UI_ARCHS)
        archs=$(shadow_lane_field rootless ARCHS) || return
        case " $archs " in
        *" arm64e "*) ;;
        *) archs="$archs arm64e" ;;
        esac
        printf '%s\n' "$archs"
        ;;
    *:ARCHS)                      theos_lane_field "$1" ARCHS ;;
    *:UI_ARCHS)                   theos_lane_field "$1" ARCHS ;;
    rootful-legacy:FLOOR)         echo "9.0" ;;
    rootful-legacy:CEILING)       echo "14.0" ;;
    rootful-legacy:PACKAGE)       echo "me.fedorovskyi.antumbra.legacy" ;;
    rootful-legacy:PACKAGE_ARCH)  echo "iphoneos-arm" ;;
    rootful-modern:FLOOR)         echo "14.0" ;;
    rootful-modern:CEILING)       echo "" ;;
    rootful-modern:PACKAGE)       echo "me.fedorovskyi.antumbra" ;;
    rootful-modern:PACKAGE_ARCH)  echo "iphoneos-arm" ;;
    rootless:FLOOR)               echo "15.0" ;;
    rootless:CEILING)             echo "" ;;
    rootless:PACKAGE)             echo "me.fedorovskyi.antumbra" ;;
    rootless:PACKAGE_ARCH)        echo "iphoneos-arm64" ;;
    roothide:FLOOR)               echo "15.0" ;;
    roothide:CEILING)             echo "18.0" ;;
    roothide:PACKAGE)             echo "me.fedorovskyi.antumbra" ;;
    roothide:PACKAGE_ARCH)        echo "iphoneos-arm64e" ;;
    *) echo "unknown lane '$1' or field '$2'" >&2; return 1 ;;
    esac
}
