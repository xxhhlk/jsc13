/*
 * jsc13 — JavaScriptCore hardening for the WebContent process on iOS 13.
 *
 * Follows the Level 2 policy of roothide/lockdown: enforce security-relevant
 * JSC Options before the first VM is created, then eliminate DoubleShape at
 * runtime. This targets the JSC/WebKit RCE stage that every modern spyware
 * chain (DarkSword, Coruna, ...) depends on.
 *
 * Levels:
 *   1 — forceGCSlowPaths, useConcurrentGC=false, haveABadTime
 *   2 — + useDFGJIT=false, useFTLJIT=false, useGenerationalGC=false
 *
 * Enforcement layers:
 *   1. JSC_* environment variables (read by Options::initialize)
 *   2. Hook JSC::Options::initialize() -> setOption()
 *   3. Hook JSC::JSGlobalObject::init(VM&) -> haveABadTime(VM&)
 */

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <substrate.h>
#include <ptrauth.h>

// ============================================================
// Configuration
// ============================================================

#define JSC13_LEVEL 2

// ============================================================
// Logging
// ============================================================
// The WebContent sandbox denies writes to /var/tmp, so the unified log is
// the only usable channel. Read it on-device with `oslog`.

static void jsc13_log(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    NSLog(@"[jsc13] %s", line);
}

// ============================================================
// Option table (single source of truth)
// ============================================================
// Phase 1 sets env var "JSC_<name>" = "<value>".
// Phase 2 calls setOption("<name>=<value>").
// DoubleShape elimination is handled by the direct haveABadTime() call.

typedef struct { const char *name; const char *value; int min_level; } opt_entry;

static const opt_entry kOptions[] = {
    { "forceGCSlowPaths",  "true",  1 },
    { "useConcurrentGC",   "false", 1 },
    { "useDFGJIT",         "false", 2 },
    { "useFTLJIT",         "false", 2 },
    { "useGenerationalGC", "false", 2 },
    { NULL, NULL, 0 }
};

// ============================================================
// Phase 1: set JSC_* environment variables
// ============================================================

static void setJSCEnvVars(void) {
    char name[64];
    for (const opt_entry *o = kOptions; o->name; o++) {
        if (o->min_level > JSC13_LEVEL) continue;
        snprintf(name, sizeof(name), "JSC_%s", o->name);
        setenv(name, o->value, 1);
    }
}

// ============================================================
// PAC-aware symbol lookup
// ============================================================
// On arm64e a function pointer obtained from the symbol table is unsigned;
// authenticate it with the standard function-pointer key/discriminator so it
// can be called from arm64e code. No-op for the arm64 slice.

static void *FindAndSignFunction(MSImageRef image, const char *symbol) {
    void *sym = MSFindSymbol(image, symbol);
    if (!sym) return NULL;
    return ptrauth_sign_unauthenticated(
               ptrauth_strip(sym, ptrauth_key_function_pointer),
               ptrauth_key_function_pointer, 0);
}

// ============================================================
// Phase 2: hook JSC::Options::initialize()
// ============================================================
// iOS 13 JSC only exports setOption(const char*) — the (const char*, bool)
// overload and notifyOptionsChanged() do not exist there.

static bool (*JSC_Options_setOption)(const char *) = NULL;
static void (*orig_JSC_Options_initialize)(void) = NULL;

static void applyOptions(const char *tag) {
    char buf[128];
    for (const opt_entry *o = kOptions; o->name; o++) {
        if (o->min_level > JSC13_LEVEL) continue;
        snprintf(buf, sizeof(buf), "%s=%s", o->name, o->value);
        bool ok = JSC_Options_setOption ? JSC_Options_setOption(buf) : false;
        jsc13_log("%s setOption(\"%s\") -> %s", tag, buf, ok ? "OK" : "FAIL");
    }
}

static void hook_JSC_Options_initialize(void) {
    orig_JSC_Options_initialize();
    jsc13_log("Options::initialize() returned");
    if (JSC13_LEVEL > 0) applyOptions("post-init");
}

// ============================================================
// Phase 3: hook JSC::JSGlobalObject::init(VM&) -> haveABadTime(VM&)
// ============================================================
// haveABadTime() converts the global object to the "bad time" state, removing
// DoubleShape. This blocks the addrof/fakeobj primitives used to bootstrap
// most JSC exploits. C++ ABI (arm64/arm64e): this=x0, vm=x1.

static void (*orig_JSC_JSGlobalObject_init)(void *, void *) = NULL;
static void (*JSC_JSGlobalObject_haveABadTime)(void *, void *) = NULL;

static void hook_JSC_JSGlobalObject_init(void *self, void *vm) {
    orig_JSC_JSGlobalObject_init(self, vm);
    if (JSC13_LEVEL >= 1 && JSC_JSGlobalObject_haveABadTime) {
        JSC_JSGlobalObject_haveABadTime(self, vm);
    }
}

// ============================================================
// Constructor
// ============================================================

%ctor {
    char exePath[PATH_MAX] = {0};
    uint32_t size = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &size) != 0) return;

    char exeCopy[PATH_MAX];
    strncpy(exeCopy, exePath, sizeof(exeCopy) - 1);
    const char *exe = basename(exeCopy);
    if (!exe || strcmp(exe, "com.apple.WebKit.WebContent") != 0) return;

    jsc13_log("===== jsc13 starting (level %d) =====", JSC13_LEVEL);

    setJSCEnvVars();
    jsc13_log("Phase 1: JSC_* env vars set");

    MSImageRef jsc = MSGetImageByName("/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore");
    if (!jsc) jsc = MSGetImageByName("JavaScriptCore");
    if (!jsc) { jsc13_log("JavaScriptCore image not found"); return; }
    jsc13_log("JavaScriptCore image @ %p", jsc);

    JSC_Options_setOption = (bool (*)(const char *))FindAndSignFunction(jsc, "__ZN3JSC7Options9setOptionEPKc");
    void *p_initialize = FindAndSignFunction(jsc, "__ZN3JSC7Options10initializeEv");
    jsc13_log("Phase 2 syms: setOption=%p initialize=%p", JSC_Options_setOption, p_initialize);
    if (JSC_Options_setOption && p_initialize) {
        MSHookFunction(p_initialize, (void *)hook_JSC_Options_initialize, (void **)&orig_JSC_Options_initialize);
        jsc13_log("Phase 2: hooked Options::initialize()");
    } else {
        jsc13_log("Phase 2: symbols missing, env-vars-only fallback");
    }

    void *p_ginit = FindAndSignFunction(jsc, "__ZN3JSC14JSGlobalObject4initERNS_2VME");
    JSC_JSGlobalObject_haveABadTime = (void (*)(void *, void *))FindAndSignFunction(jsc, "__ZN3JSC14JSGlobalObject12haveABadTimeERNS_2VME");
    jsc13_log("Phase 3 syms: init=%p haveABadTime=%p", p_ginit, JSC_JSGlobalObject_haveABadTime);
    if (p_ginit && JSC_JSGlobalObject_haveABadTime) {
        MSHookFunction(p_ginit, (void *)hook_JSC_JSGlobalObject_init, (void **)&orig_JSC_JSGlobalObject_init);
        jsc13_log("Phase 3: hooked JSGlobalObject::init() -> haveABadTime()");
    } else {
        jsc13_log("Phase 3: symbols missing");
    }

    jsc13_log("===== jsc13 init complete =====");
}
