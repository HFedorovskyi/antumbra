#!/bin/sh
# Keep build lanes and package control templates aligned.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
. "$ROOT/build-support/lanes.sh"

status=0

fail() {
    echo "LANE CONTRACT: $*" >&2
    status=1
}

for lane in rootful-legacy rootful-modern rootless roothide; do
    template="$ROOT/packaging/controls/control.$lane.in"
    [ -f "$template" ] || { fail "$lane has no control template"; continue; }

    package=$(shadow_lane_field "$lane" PACKAGE)
    floor=$(shadow_lane_field "$lane" FLOOR)
    ceiling=$(shadow_lane_field "$lane" CEILING)
    target=$(shadow_lane_field "$lane" TARGET)
    archs=$(shadow_lane_field "$lane" ARCHS)
    ui_archs=$(shadow_lane_field "$lane" UI_ARCHS)
    sdk=${target#iphone:clang:}
    sdk=${sdk%%:*}
    rendered=$("$ROOT/scripts/gen-control.sh" "$lane") || { fail "$lane control template failed to render"; continue; }

    if [ "$lane" = rootless ]; then
        expected_ui=$archs
        case " $expected_ui " in
            *" arm64e "*) ;;
            *) expected_ui="$expected_ui arm64e" ;;
        esac
        [ "$ui_archs" = "$expected_ui" ] || fail "rootless UI architectures '$ui_archs' != '$expected_ui'"
    else
        [ "$ui_archs" = "$archs" ] || fail "$lane UI architectures '$ui_archs' != '$archs'"
    fi
    deps=$(printf '%s\n' "$rendered" | sed -n 's/^Depends: //p')
    actual_package=$(printf '%s\n' "$rendered" | sed -n 's/^Package: //p')

    [ -n "$sdk" ] && [ "$sdk" != "$target" ] || fail "$lane has no SDK in TARGET '$target'"
    [ "$actual_package" = "$package" ] || fail "$lane package '$actual_package' != '$package'"
    # The rootless/RootHide Theos schemes rewrite the control template's
    # iphoneos-arm architecture during packaging.  The final package
    # architecture is checked by scripts/check-compat.sh against PACKAGE_ARCH.

    case "$deps" in
        *"firmware (>= $floor)"*) ;;
        *) fail "$lane lacks firmware >= $floor" ;;
    esac

    if [ -n "$ceiling" ]; then
        case "$deps" in
            *"firmware (<< $ceiling)"*) ;;
            *) fail "$lane lacks firmware << $ceiling" ;;
        esac
    fi
done

settings_rootless=$(sed -n '/^ifeq ($(SHADOW_LANE),rootless)$/,/^else$/p' \
    "$ROOT/src/ShadowSettings.bundle/Makefile")
case "$settings_rootless" in
    *'override ARCHS := $(call lane_field,$(SHADOW_LANE),UI_ARCHS)'*) ;;
    *) fail "rootless Settings does not use UI_ARCHS" ;;
esac
case "$settings_rootless" in
    *'../Shadow.framework/Settings.m ../Shadow.framework/SettingsMigration.m ../Shadow.framework/HookConfiguration.m'*) ;;
    *) fail "rootless Settings does not embed its Foundation implementation" ;;
esac
case "$settings_rootless" in
    *'ShadowSettings_CFLAGS += -DSHADOW_SETTINGS_EMBEDDED'*) ;;
    *) fail "rootless Settings does not enable embedded path handling" ;;
esac
case "$settings_rootless" in
    *'ShadowSettings_EXTRA_FRAMEWORKS += Shadow'*) fail "rootless Settings still links Shadow.framework" ;;
esac

grep -Fq '"ARCHS=$(shadow_lane_field "$FLAVOR" UI_ARCHS)"' \
    "$ROOT/.github/scripts/build-deps.sh" || fail "AltList does not use UI_ARCHS"
grep -Fq 'SHADOW_EXPECTED_ARCHS="$(shadow_lane_field "$PROFILE" UI_ARCHS)"' \
    "$ROOT/scripts/check-compat.sh" || fail "Settings compatibility does not use UI_ARCHS"

[ "$status" -eq 0 ] || exit "$status"
echo "OK: build lanes, UI architectures, and package metadata agree"
