# Antumbra — hardened fork of Shadow (iOS 15–18)

**[English](#english) · [Русский](#русский)**

---

## English

Antumbra is a fork of [Shadow](https://github.com/jjolano/shadow) © 2023 jjolano
(BSD-3-Clause): a jailbreak detection bypass hardened for iOS 15–18 and rootless
Dopamine, with its own **English / Russian** pane language switch. Ships as
`me.fedorovskyi.antumbra` (`4.1.1`).

Not affiliated with, sponsored by or endorsed by the original author. Internal
core names and the prefs domain are kept so existing installations and settings
keep working. Licensed BSD-3-Clause, see [LICENSE](LICENSE) and
[NOTICE](NOTICE).

### What this fork adds

* English/Russian pane switch, English by default.
* Extra adapters for third-party detection SDKs and a shared filesystem/system
  query layer for iOS 18.
* Root-side `shdwbl` daemon and CLI: per-app opt-out, package snapshots and
  rollback.
* Rootless build: thin arm64 payload with an arm64e preference bundle.

### Install

Grab the `.deb` from [Releases](https://github.com/HFedorovskyi/antumbra/releases)
and install it with Sileo/Zebra/Filza or `dpkg -i`. Needs `AltList` + `libSandy`
(opa334) and `HookKit >= 3.0.4` (jjolano); `Injection Foundation` (PoomSmart) is
recommended.

* From upstream `me.jjolano.shadow` Antumbra installs directly: the package
  declares `Provides`/`Replaces`/`Conflicts` and replaces it without `--force`.
* From the previous fork `me.fedorovskyi.shadow` (4.0.39~hf1 and older), remove
  the old package first: `dpkg -r me.fedorovskyi.shadow`, then install
  `me.fedorovskyi.antumbra`. The old package's own conflict against the shared
  `Provides` makes a plain `dpkg -i` over it fail.
* Settings and exception lists are kept; the prefs domain is unchanged. If
  `dpkg -l` shows `rc  me.fedorovskyi.shadow` or `ic  me.jjolano.shadow`,
  clear the record with `dpkg -P <name>`.

### Use

Settings → Antumbra. Global switches and per-app settings; the pane language is
switched there as well (English by default). `shdw -d` keeps the app ruleset in
sync.

### Compatibility

| Lane | Package | iOS | Tested |
| --- | --- | --- | --- |
| Rootless | `iphoneos-arm64` | **15.0 – 18.x** | 18.6.2, Dopamine 3 |
| Rootful modern | `iphoneos-arm` | 14.0 – 18.x | not tested |
| RootHide | `iphoneos-arm64e` | 15.0 – 17.x | not tested |
| Rootful legacy | `iphoneos-arm` (`me.fedorovskyi.antumbra.legacy`) | 9.0 – 13.x | not tested |

Ranges come from the control files. Only the rootless lane is tested on a
device, on iOS 18.6.2 (Dopamine 3): pane, watcher, blacklistd, injection into
third-party apps. The other lanes are built in CI but untested on devices; an
open-ended range does not promise support for future iOS releases.

### Troubleshooting

* Disable other tweaks per-app (Choicy).
* Downgrade the app; don't stack multiple bypass tweaks.
* Rootless/semi-untethered: test in stock jailed state to isolate.

### Building

Requires [Theos](https://theos.dev) and the `modern21` toolchain for the arm64e
preference bundle:

```sh
MODERN_TOOLCHAIN=/opt/theos/toolchain/modern21/linux/iphone \
    /opt/theos/bin/setup-modern-toolchain.sh /usr/bin/clang-21
.github/scripts/build-deps.sh rootless
./build.sh rootless
```

Lanes: `rootful-legacy`, `rootful-modern`, `rootless`, `roothide`. See
`build-support/lanes.sh` for the matrix. Tests: `make -C tests test`
([details](tests/README.md)).

### Legal

Upstream code: Copyright (c) 2023, jjolano, BSD 3-Clause. Fork modifications:
Copyright (c) 2026, HRYHORII FEDOROVSKYI, same license. See [LICENSE](LICENSE)
and [NOTICE](NOTICE); the notice, conditions and disclaimer are also shipped
inside every package.

---

## Русский

Antumbra — форк [Shadow](https://github.com/jjolano/shadow) © 2023 jjolano
(BSD-3-Clause): обход детекта джейлбрейка, усиленный под iOS 15–18 и rootless
Dopamine, с отдельным переключателем языка панели **English / Русский**.
Ставится как `me.fedorovskyi.antumbra` (версия `4.1.1`).

Проект не связан с автором оригинала и не одобрен им. Внутренние имена ядра и
домен настроек сохранены, чтобы прежние установки и настройки продолжали
работать. Лицензия — BSD-3-Clause, полные тексты в [LICENSE](LICENSE) и
[NOTICE](NOTICE).

### Что добавлено

* Переключатель языка панели: English/Russian, по умолчанию English.
* Дополнительные adapter'ы для сторонних детекторов и общий слой подмены
  файловых/системных запросов для iOS 18.
* Root-side демон `shdwbl` и CLI: per-app opt-out, snapshots и откат обновлений
  пакета.
* Сборка rootless: payload — thin arm64, preference bundle — arm64e.

### Установка

Возьми `.deb` из [Releases](https://github.com/HFedorovskyi/antumbra/releases)
и поставь через Sileo/Zebra/Filza или `dpkg -i`. Нужны `AltList`, `libSandy`
(opa334) и `HookKit >= 3.0.4` (jjolano); рекомендуется `Injection Foundation`
(PoomSmart).

* С апстрима `me.jjolano.shadow` Antumbra ставится напрямую: пакет объявляет
  `Provides`/`Replaces`/`Conflicts` и заменяет его без `--force`.
* С прошлого форка `me.fedorovskyi.shadow` (4.0.39~hf1 и раньше) сначала удали
  старый пакет: `dpkg -r me.fedorovskyi.shadow`, затем поставь
  `me.fedorovskyi.antumbra`. Старый пакет сам конфликтует с общим `Provides`,
  поэтому `dpkg -i` поверх него откажется.
* Настройки и списки исключений сохраняются: домен prefs не меняется. Если
  `dpkg -l` показывает `rc  me.fedorovskyi.shadow` или `ic  me.jjolano.shadow`,
  запись убирается командой `dpkg -P <имя>`.

### Использование

Настройки → Antumbra. Глобальные переключатели и настройки по приложениям; язык
панели переключается там же (English по умолчанию). `shdw -d` синхронизирует
ruleset приложений.

### Совместимость

| Лейн | Пакет | iOS | Проверено |
| --- | --- | --- | --- |
| Rootless | `iphoneos-arm64` | **15.0 – 18.x** | 18.6.2, Dopamine 3 |
| Rootful modern | `iphoneos-arm` | 14.0 – 18.x | не проверялся |
| RootHide | `iphoneos-arm64e` | 15.0 – 17.x | не проверялся |
| Rootful legacy | `iphoneos-arm` (`me.fedorovskyi.antumbra.legacy`) | 9.0 – 13.x | не проверялся |

Диапазоны взяты из control-файлов. На устройстве проверен только rootless-лейн
на iOS 18.6.2 (Dopamine 3): панель, watcher, blacklistd, инъекция в сторонние
приложения. Остальные лейны собираются в CI, но не проверялись на живых
устройствах; открытый диапазон не обещает совместимость с будущими релизами
iOS.

### Если что-то не работает

* Отключи другие твики для конкретного приложения (Choicy).
* Откати версию приложения; не ставь несколько bypass-твиков сразу.
* Rootless/semi-untethered: проверяй в обычном (неджейлбрейкнутом) состоянии,
  чтобы отделить проблему от самого джейлбрейка.

### Сборка

Нужны [Theos](https://theos.dev) и тулчейн `modern21` для arm64e preference
bundle:

```sh
MODERN_TOOLCHAIN=/opt/theos/toolchain/modern21/linux/iphone \
    /opt/theos/bin/setup-modern-toolchain.sh /usr/bin/clang-21
.github/scripts/build-deps.sh rootless
./build.sh rootless
```

Лейны: `rootful-legacy`, `rootful-modern`, `rootless`, `roothide`; матрица — в
`build-support/lanes.sh`. Тесты: `make -C tests test`
([подробности](tests/README.md)).

### Лицензия

Код апстрима: Copyright (c) 2023, jjolano, BSD 3-Clause. Изменения форка:
Copyright (c) 2026, HRYHORII FEDOROVSKYI, та же лицензия. См. [LICENSE](LICENSE)
и [NOTICE](NOTICE); текст лицензии, условия и отказ от гарантий также лежат
внутри каждого пакета.
