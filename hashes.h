// ===================================================================================
// C++ Verifier Output - Generated Hashes (v2 - Comprehensive Unhooking)
// Copy this entire block into your C++ loader's header file.
// ===================================================================================

// --- DLL Hashes (Case-Insensitive, from WIDE strings) ---
#define HASH_KERNEL32_DLL_W              0x7040ee75
#define HASH_USER32_DLL_W                0x5a6bd3f3
#define HASH_NTDLL_DLL_W                 0x22d3b5ed

// --- API Function Hashes (Case-Sensitive, from ANSI strings) ---

// -- Core Windows API --
// SUCCESS: HASH_LOADLIBRARYW :: LoadLibraryW
#define HASH_LOADLIBRARYW                        0x5fbff111
// SUCCESS: HASH_CREATEFILEW :: CreateFileW
#define HASH_CREATEFILEW                         0xeb96c610
// SUCCESS: HASH_CREATEFILEMAPPINGW :: CreateFileMappingW
#define HASH_CREATEFILEMAPPINGW                  0xf33ffc9c
// SUCCESS: HASH_MAPVIEWOFFILE :: MapViewOfFile
#define HASH_MAPVIEWOFFILE                       0x11deb0b3
// SUCCESS: HASH_UNMAPVIEWOFFILE :: UnmapViewOfFile
#define HASH_UNMAPVIEWOFFILE                     0xd639f256
// SUCCESS: HASH_CLOSEHANDLE :: CloseHandle
#define HASH_CLOSEHANDLE                         0x3870ca07
// SUCCESS: HASH_VIRTUALPROTECT :: VirtualProtect
#define HASH_VIRTUALPROTECT                      0x844ff18d
// SUCCESS: HASH_GETFILESIZE :: GetFileSize
#define HASH_GETFILESIZE                         0x7891c520
// SUCCESS: HASH_READFILE :: ReadFile
#define HASH_READFILE                            0x71019921
// SUCCESS: HASH_GETSYSTEMDIRECTORYW :: GetSystemDirectoryW
#define HASH_GETSYSTEMDIRECTORYW                 0xe643c476
// SUCCESS: HASH_CREATETOOLHELP32SNAPSHOT :: CreateToolhelp32Snapshot
#define HASH_CREATETOOLHELP32SNAPSHOT            0x66851295
// SUCCESS: HASH_PROCESS32FIRSTW :: Process32FirstW
#define HASH_PROCESS32FIRSTW                     0xe18fc6e8
// SUCCESS: HASH_PROCESS32NEXTW :: Process32NextW
#define HASH_PROCESS32NEXTW                      0x9307647f
// SUCCESS: HASH_OPENPROCESS :: OpenProcess
#define HASH_OPENPROCESS                         0x7136fdd6
// SUCCESS: HASH_CREATEPROCESSW :: CreateProcessW
#define HASH_CREATEPROCESSW                      0xaeb52e2f
// SUCCESS: HASH_VIRTUALALLOCEX :: VirtualAllocEx
#define HASH_VIRTUALALLOCEX                      0xf36e5ab4
// SUCCESS: HASH_WRITEPROCESSMEMORY :: WriteProcessMemory
#define HASH_WRITEPROCESSMEMORY                  0x6f22e8c8
// SUCCESS: HASH_QUEUEUSERAPC :: QueueUserAPC
#define HASH_QUEUEUSERAPC                        0x76c0c4bd
// SUCCESS: HASH_RESUMETHREAD :: ResumeThread
#define HASH_RESUMETHREAD                        0x74162a6e
// SUCCESS: HASH_MESSAGEBOXA :: MessageBoxA
#define HASH_MESSAGEBOXA                         0x384f14b4

// -- Functions for Comprehensive Unhooking (ntdll.dll) --
// SUCCESS: HASH_NTALLOCATEVIRTUALMEMORY :: NtAllocateVirtualMemory
#define HASH_NTALLOCATEVIRTUALMEMORY             0x6793c34c
// SUCCESS: HASH_NTPROTECTVIRTUALMEMORY :: NtProtectVirtualMemory
#define HASH_NTPROTECTVIRTUALMEMORY              0x82962c8
// SUCCESS: HASH_NTWRITEVIRTUALMEMORY :: NtWriteVirtualMemory
#define HASH_NTWRITEVIRTUALMEMORY                0x95f3a792
// SUCCESS: HASH_NTCREATETHREADEX :: NtCreateThreadEx
#define HASH_NTCREATETHREADEX                    0xcb0c2130
// SUCCESS: HASH_NTQUEUEAPCTHREAD :: NtQueueApcThread
#define HASH_NTQUEUEAPCTHREAD                    0xd4612238
// SUCCESS: HASH_NTRESUMETHREAD :: NtResumeThread
#define HASH_NTRESUMETHREAD                      0x2c7b3d30
// SUCCESS: HASH_NTCLOSE :: NtClose
#define HASH_NTCLOSE                             0x8b8e133d

// --- End Verifier Output ---
