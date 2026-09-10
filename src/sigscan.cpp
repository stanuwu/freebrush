// Byte-pattern scanning implementation.
#include "sigscan.h"
#include <vector>

namespace {

/// One parsed pattern byte: a value plus whether it is a wildcard.
struct PatByte {
    uint8_t value;
    bool wild;
};

/// Parse a space-separated hex pattern with "??"/"?" wildcards.
bool parse_pattern(const char* pattern, std::vector<PatByte>& out) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (const char* p = pattern; *p;) {
        if (*p == ' ') { ++p; continue; }
        if (*p == '?') {
            out.push_back({0, true});
            ++p;
            if (*p == '?') ++p;
            continue;
        }
        int hi = hexval(p[0]);
        int lo = p[1] ? hexval(p[1]) : -1;
        if (hi < 0 || lo < 0) return false;
        out.push_back({static_cast<uint8_t>((hi << 4) | lo), false});
        p += 2;
    }
    return !out.empty();
}

/// True if `pat` matches the bytes at `mem`.
bool match_at(const uint8_t* mem, const std::vector<PatByte>& pat) {
    for (size_t i = 0; i < pat.size(); ++i)
        if (!pat[i].wild && mem[i] != pat[i].value) return false;
    return true;
}

/// Validate the PE headers of a mapped module; return its NT headers or null.
IMAGE_NT_HEADERS* pe_nt(HMODULE module) {
    auto* base = reinterpret_cast<uint8_t*>(module);
    if (!base) return nullptr;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    return (nt->Signature == IMAGE_NT_SIGNATURE) ? nt : nullptr;
}

/// Invoke fn(start, size) per section; `exec_only` limits to executable ones.
/// fn returns false to stop the walk early.
template <class F>
void for_sections(HMODULE module, bool exec_only, F&& fn) {
    auto* nt = pe_nt(module);
    if (!nt) return;
    auto* base = reinterpret_cast<uint8_t*>(module);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (exec_only && !(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!fn(base + sec->VirtualAddress, static_cast<size_t>(sec->Misc.VirtualSize)))
            return;
    }
}

// x86-64 instruction decode constants.
constexpr int kNearRelLen = 5;                        // E8/E9 <rel32>
constexpr uint8_t kRexW = 0x48, kLeaOp = 0x8D;        // lea r64, [rip+disp32]
constexpr uint8_t kModRmMask = 0xC7, kModRmRip = 0x05; // mod=00, rm=101 (rip-relative)
constexpr int kLeaLen = 7, kLeaDispOff = 3;
constexpr uint8_t kInt3 = 0xCC;                       // MSVC inter-function padding
constexpr size_t kHeaderGuard = 0x1000;               // never scan into the PE headers

} // namespace

uint8_t* sig_scan_unique(HMODULE module, const char* pattern) {
    std::vector<PatByte> pat;
    if (!parse_pattern(pattern, pat)) {
        fb_log(FB_TAG "bad pattern: %s", pattern);
        return nullptr;
    }
    uint8_t* found = nullptr;
    int hits = 0;
    for_sections(module, true, [&](uint8_t* start, size_t size) {
        if (size < pat.size()) return true;
        uint8_t* end = start + size - pat.size();
        for (uint8_t* p = start; p <= end; ++p) {
            if (!match_at(p, pat)) continue;
            if (++hits == 1) found = p;
            else return false; // second match -> ambiguous, stop
        }
        return true;
    });
    return (hits == 1) ? found : nullptr;
}

int sig_scan_all(HMODULE module, const char* pattern, uint8_t** out, int max) {
    if (!out || max <= 0) return 0;
    std::vector<PatByte> pat;
    if (!parse_pattern(pattern, pat)) return 0;
    int n = 0;
    for_sections(module, true, [&](uint8_t* start, size_t size) {
        if (size < pat.size()) return true;
        uint8_t* end = start + size - pat.size();
        for (uint8_t* p = start; p <= end && n < max; ++p)
            if (match_at(p, pat)) out[n++] = p;
        return n < max;
    });
    return n;
}

uint8_t* find_bytes(HMODULE module, const void* bytes, size_t n) {
    if (!bytes || !n) return nullptr;
    auto* pat = reinterpret_cast<const uint8_t*>(bytes);
    uint8_t* hit = nullptr;
    for_sections(module, false, [&](uint8_t* start, size_t size) {
        if (size < n) return true;
        uint8_t* end = start + size - n;
        for (uint8_t* p = start; p <= end; ++p)
            if (memcmp(p, pat, n) == 0) { hit = p; return false; }
        return true;
    });
    return hit;
}

uint8_t* find_rip_lea_ref(HMODULE module, uint8_t* data) {
    if (!data) return nullptr;
    uint8_t* found = nullptr;
    int hits = 0;
    for_sections(module, true, [&](uint8_t* start, size_t size) {
        if (size < kLeaLen) return true;
        uint8_t* end = start + size - kLeaLen;
        for (uint8_t* p = start; p <= end; ++p) {
            if (p[0] != kRexW || p[1] != kLeaOp || (p[2] & kModRmMask) != kModRmRip) continue;
            int32_t disp = *reinterpret_cast<int32_t*>(p + kLeaDispOff);
            if (p + kLeaLen + disp != data) continue;
            if (++hits == 1) found = p;
            else return false; // ambiguous
        }
        return true;
    });
    return (hits == 1) ? found : nullptr;
}

uint8_t* rel32_target(uint8_t* site) {
    if (!site) return nullptr;
    return site + kNearRelLen + *reinterpret_cast<int32_t*>(site + 1);
}

uint8_t* rip_target(uint8_t* site, int disp_off, int instr_len) {
    if (!site) return nullptr;
    return site + instr_len + *reinterpret_cast<int32_t*>(site + disp_off);
}

uint8_t* function_start(HMODULE module, uint8_t* inside) {
    if (!inside) return nullptr;
    auto* base = reinterpret_cast<uint8_t*>(module);
    for (uint8_t* p = inside; p > base + kHeaderGuard; --p)
        if (p[-1] == kInt3 && p[-2] == kInt3) return p; // entry follows int3 padding
    return nullptr;
}

bool write_code(void* addr, const void* data, size_t n) {
    if (!addr || !data || !n) return false;
    DWORD old = 0;
    if (!VirtualProtect(addr, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(addr, data, n);
    VirtualProtect(addr, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, n);
    return true;
}
