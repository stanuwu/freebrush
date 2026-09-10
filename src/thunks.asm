; Export thunks for the version API. Each jumps to the resolved real function
; in g_real[i] (filled by proxy_init). A plain jmp preserves all arguments,
; registers, and the return value, so no per-function prototype is needed.
OPTION CASEMAP:NONE

EXTERN g_real:QWORD

.CODE

PROXY MACRO fname, idx
PUBLIC fname
fname PROC
    jmp QWORD PTR [g_real + idx*8]
fname ENDP
ENDM

PROXY GetFileVersionInfoA,        0
PROXY GetFileVersionInfoByHandle, 1
PROXY GetFileVersionInfoExA,      2
PROXY GetFileVersionInfoExW,      3
PROXY GetFileVersionInfoSizeA,    4
PROXY GetFileVersionInfoSizeExA,  5
PROXY GetFileVersionInfoSizeExW,  6
PROXY GetFileVersionInfoSizeW,    7
PROXY GetFileVersionInfoW,        8
PROXY VerFindFileA,               9
PROXY VerFindFileW,               10
PROXY VerInstallFileA,            11
PROXY VerInstallFileW,            12
PROXY VerQueryValueA,             13
PROXY VerQueryValueW,             14

END
