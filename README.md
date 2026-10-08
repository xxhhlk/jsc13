# jsc13

A JavaScriptCore hardening tweak for **iOS 13** (rootful, Substitute), ported
from the **Level 2** policy of [roothide/lockdown](https://github.com/roothide/lockdown).

It hardens the WebKit **WebContent** process against the JavaScriptCore
exploitation primitives that every modern iOS spyware chain needs for its first
stage — the in-browser JavaScript RCE (the DarkSword / Coruna style kits all
start there).

Tested on an iPhone SE2 (A13) running iOS 13.4.1.

---

## Why this exists

Modern iOS exploit kits are delivered as ordinary web pages: the chain begins
with a WebKit / JavaScriptCore RCE, then escalates to the kernel. Break the
first stage and the whole chain stops.

The catch is that this cannot be done by patching individual CVEs — they keep
coming. Instead, `jsc13` removes the *primitives* those bugs are built on:

* `haveABadTime()` eliminates `DoubleShape`, which removes the `addrof` /
  `fakeobj` primitives used to bootstrap almost every JSC exploit.
* Disabling the DFG and FTL JIT tiers removes the speculative-optimisation
  surface that most type-confusion bugs live in.

The better-known [AntiDarkSword](https://github.com/EolnMsuk/AntiDarkSword) takes
a different route (disable JIT via the `_WKProcessPoolConfiguration.JITEnabled`
SPI). On iOS 13 that SPI is read when the WebContent process is *launched*, so
setting it from `WKWebViewConfiguration` after the fact has no effect — its
`disableJIT15` path does not work there. Setting the JSC options directly
*inside* the WebContent process does.

## How it works

Three enforcement layers, all running inside the WebContent process:

| Layer | Mechanism | When |
| --- | --- | --- |
| 1 | `setenv("JSC_<name>", "<value>")` | tweak constructor, before `Options::initialize()` |
| 2 | hook `JSC::Options::initialize()` → `Options::setOption("<name>=<value>")` | right after JSC reads its options |
| 3 | hook `JSC::JSGlobalObject::init(VM&)` → call `haveABadTime(VM&)` | on every global object, before any script runs |

Level 2 options:

| Option | Value | Purpose |
| --- | --- | --- |
| `forceGCSlowPaths` | `true` | keep the GC on the slow, checked path |
| `useConcurrentGC` | `false` | no concurrent-GC races |
| `useDFGJIT` | `false` | disable the DFG speculative optimiser |
| `useFTLJIT` | `false` | disable the FTL |
| `useGenerationalGC` | `false` | simpler GC |

Levels are selected with `JSC13_LEVEL` in `Tweak.x`:

| Level | Effect |
| --- | --- |
| 0 | disabled |
| 1 | `forceGCSlowPaths`, `useConcurrentGC=false`, `haveABadTime` |
| 2 | + `useDFGJIT=false`, `useFTLJIT=false`, `useGenerationalGC=false` |
| 3 | + all JIT tiers disabled, inline caches disabled |

The upstream XPC layer (which injects `JSC_*` variables into the WebContent
bootstrap message) is intentionally **omitted**: it needs XPC headers that the
iOS 13 SDK does not ship, and layers 2 and 3 are sufficient on their own.

## Injection scope

The filter matches **only** the WebContent (renderer / JavaScript) process:

```
{ Filter = { Bundles = ( "com.apple.WebKit.WebContent" );
             Executables = ( "com.apple.WebKit.WebContent" ); }; }
```

A runtime guard on the executable basename (`com.apple.WebKit.WebContent`) backs
this up. The tweak is **not** injected into:

| Process | Why not |
| --- | --- |
| `com.apple.WebKit.Networking` | network only, no JavaScript |
| `com.apple.WebKit.GPU` | compositing only |
| MobileSafari / SpringBoard / other apps | the UI process, no JSC execution |

Because **every** `WKWebView` — Safari and third-party apps alike — renders in
the same `com.apple.WebKit.WebContent` process, all WebKit web content is
covered with no per-app configuration.

The tweak applies to WebContent processes spawned *after* installation. An
already-running WebContent process keeps its unhardened code until it exits, so
kill it (or let it exit) to pick up the change.

## Requirements

* iOS 13.x, rootful jailbreak with Substitute
* [Theos](https://theos.dev)
* A compiler that emits **arm64e ABI v1** (see below)

## Building

```sh
export THEOS=~/theos
make package FINALPACKAGE=1
```

The Makefile builds both slices:

```make
ARCHS  = arm64 arm64e
TARGET = iphone:clang:14.5:13.0
```

### The arm64e slice must be ABI v1

Safari and the WebKit processes are arm64e on A12+ devices. Because of pointer
authentication, an **arm64 binary cannot be loaded into an arm64e process**, so
an arm64e slice is mandatory — the `arm64`-only "legacy" build that upstream
projects sometimes ship cannot inject into WebKit at all.

The arm64e slice must additionally be **ABI v1** (iOS 12.0–13.7). Which version
you get is decided by the *compiler*, not the SDK:

| Toolchain | arm64e ABI | Loads on |
| --- | --- | --- |
| clang < 12 (Xcode ≤ 11.7) | **v1** | iOS 12 – 13.7 |
| clang ≥ 12 (Xcode 12+) | v2 | iOS 14+ only |

`SDK 14.5` is used for the headers, but the **deployment target stays 13.0** and
the compiler must be clang 11 (Xcode 11.7). Verify the slice afterwards:

```sh
otool -hv .theos/obj/arm64e/jsc13.dylib     # caps must be 0x00 (v1)
vtool -show-build .theos/obj/arm64e/jsc13.dylib   # minos 13.0
```

## Install

```sh
dpkg -i com.xxhhlk.jsc13_1.0.0_iphoneos-arm.deb
launchctl start science.xnu.substitute.reload
```

`substituted` caches the tweak list at launch; a bare `dpkg -i` does **not**
trigger a reload, so the `launchctl` line is required. (The reload also
resprangs.)

## Verifying

### The log

The WebContent sandbox **denies writes to `/var/tmp`**, so the tweak cannot use
a file log — it logs via `NSLog` to the unified log instead. Read it on-device
with [`oslog`](https://github.com/limneos/oslog):

```sh
oslog > /var/tmp/wc.log &
# force a fresh WebContent process (kill the existing ones, reload a page)
grep jsc13 /var/tmp/wc.log
```

`tools/capture_oslog.sh` does exactly this. Expected output:

```
[jsc13] ===== jsc13 starting (level 2) =====
[jsc13] Phase 1: JSC_* env vars set
[jsc13] Phase 2: hooked Options::initialize()
[jsc13] Phase 3: hooked JSGlobalObject::init() -> haveABadTime()
[jsc13] post-init setOption("forceGCSlowPaths=true")   -> OK
[jsc13] post-init setOption("useConcurrentGC=false")   -> OK
[jsc13] post-init setOption("useDFGJIT=false")         -> OK
[jsc13] post-init setOption("useFTLJIT=false")         -> OK
[jsc13] post-init setOption("useGenerationalGC=false") -> OK
```

`-> OK` means the option name was accepted and applied. If a symbol is missing
the tweak logs it and continues (it fails soft rather than crashing WebContent).

### The effect

A simple JSC benchmark (`Math.sqrt` in a 3,000,000-iteration loop) run in Safari,
before and after, on the same device:

| State | `bench_ms` |
| --- | --- |
| jsc13 not installed | **6 – 41 ms** |
| jsc13, Level 2 | **111 – 216 ms** |

Roughly **8–10× slower** — the signature of the DFG and FTL being off. Web
content stays usable, and WebAssembly is unaffected (`wasm=ok_42` before and
after), which is correct: Level 2 does not disable Wasm.

## iOS 13 JSC specifics

iOS 13.4.1's JavaScriptCore differs from modern releases in ways that matter:

* Only `JSC::Options::setOption(char const*)` exists — the
  `(char const*, bool)` overload and `notifyOptionsChanged()` do **not**.
* These symbols *are* present (checked against the device's
  `dyld_shared_cache_arm64e`):
  * `__ZN3JSC7Options10initializeEv`
  * `__ZN3JSC7Options9setOptionEPKc`
  * `__ZN3JSC14JSGlobalObject4initERNS_2VME`
  * `__ZN3JSC14JSGlobalObject12haveABadTimeERNS_2VME`

The hooks are installed by looking these symbols up in the
`JavaScriptCore.framework` image and authenticating the function pointers
(`ptrauth_sign_unauthenticated(..., ptrauth_key_function_pointer, 0)`), so they
work on arm64e. On the arm64 slice the signing is a no-op.

## Notes and limitations

* **This patches no CVE.** It removes the JSC exploitation surface those CVEs
  rely on. A future bug in a primitive that is still enabled (the baseline JIT,
  the interpreter, the regexp engine at Level 2, …) is not covered.
* Level 2 keeps the baseline JIT. Level 3 disables every JIT tier at a much
  larger performance cost.
* Only the WebContent process is hardened; WebKit's Networking and GPU processes
  do not execute JavaScript.
* The tweak depends on private, unexported C++ symbols. A future JavaScriptCore
  change can break the hooks. It fails soft (logs and continues) rather than
  crashing WebContent.
* Verified against the DarkSword / Coruna class of kits only in the sense that
  the JSC hardening is active; it has not been tested against a live exploit
  sample.

## License

MIT — see [LICENSE](LICENSE).
