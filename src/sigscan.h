// Byte-pattern scanning over a loaded module's executable sections.
#pragma once

#include "common.h"

/// Scan every executable section of a module for a masked byte pattern.
/// Pattern is a space-separated hex string; "??" (or "?") is a wildcard byte,
/// e.g. "89 05 ?? ?? ?? ?? E8". Returns the single match address, or nullptr
/// if there are zero matches or more than one (ambiguous = unsafe to hook).
uint8_t* sig_scan_unique(HMODULE module, const char* pattern);

/// Find up to `max` matches of a masked pattern across executable sections.
/// Writes match addresses into `out` and returns the count found (<= max).
/// Use when a signature intentionally matches several identical functions.
int sig_scan_all(HMODULE module, const char* pattern, uint8_t** out, int max);

/// Follow a near CALL/JMP rel32 at `site` (opcode byte at site) to its target.
/// target = site + 5 + *(int32*)(site + 1).
uint8_t* rel32_target(uint8_t* site);

/// Resolve a RIP-relative data address encoded in an instruction.
/// addr = site + instr_len + *(int32*)(site + disp_off).
uint8_t* rip_target(uint8_t* site, int disp_off, int instr_len);

/// Walk backwards from an in-function address to the function entry, using the
/// int3 (0xCC) padding MSVC places between functions. Best-effort.
uint8_t* function_start(HMODULE module, uint8_t* inside);

/// Find the first occurrence of a raw byte run anywhere in the module image
/// (any section, e.g. a string in .rdata). Returns nullptr if absent.
uint8_t* find_bytes(HMODULE module, const void* bytes, size_t n);

/// Find the single `lea r64, [rip+disp]` in executable code whose target is
/// `data`. Returns nullptr if there are zero or more than one such refs.
uint8_t* find_rip_lea_ref(HMODULE module, uint8_t* data);

/// Write n bytes into executable memory (toggles page protection, flushes the
/// instruction cache). For the rare mid-function branch a detour cannot cover.
bool write_code(void* addr, const void* data, size_t n);
