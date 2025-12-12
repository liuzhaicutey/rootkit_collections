#include <pch.h>
#include <windows.h>
#include <stdio.h>
#include <strsafe.h> 

typedef UINT_PTR UPTR;


typedef BOOL(WINAPI* MainEntryPoint)(HINSTANCE, DWORD, LPVOID);


typedef VOID(NTAPI* PIMAGE_TLS_CALLBACK)(LPVOID, DWORD, LPVOID);



VOID ProcessRelocations(PIMAGE_NT_HEADERS pNtHeaders, BYTE* pNewImageBase, UPTR oldBase, UPTR newBase) {
    if (newBase == oldBase) {
        return;
    }

    PIMAGE_DATA_DIRECTORY pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pDataDir->VirtualAddress == 0 || pDataDir->Size == 0) {
        OutputDebugStringA("Reassembler: No relocation directory found.\n");
        return;
    }

    UPTR delta = newBase - oldBase;
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pNewImageBase + pDataDir->VirtualAddress);
    PIMAGE_BASE_RELOCATION pRelocEnd = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pDataDir->Size);

    while (pReloc < pRelocEnd && pReloc->SizeOfBlock > 0) {
        BYTE* pBlockData = pNewImageBase + pReloc->VirtualAddress;
        DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < numEntries; ++i) {
            WORD relocEntry = ((WORD*)(pReloc + 1))[i];
            if (relocEntry == 0) continue;

            WORD type = relocEntry >> 12;
            WORD offset = relocEntry & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                *(UPTR*)(pBlockData + offset) += delta;
            }
        }
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }
    OutputDebugStringA("Reassembler: Relocations processed.\n");
}


VOID ProcessImports(PIMAGE_NT_HEADERS pNtHeaders, BYTE* pNewImageBase) {
    PIMAGE_DATA_DIRECTORY pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pDataDir->VirtualAddress == 0 || pDataDir->Size == 0) {
        OutputDebugStringA("Reassembler: No import directory found.\n");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pNewImageBase + pDataDir->VirtualAddress);

    for (; pImportDesc->Name != 0; ++pImportDesc) {
        char* szDllName = (char*)(pNewImageBase + pImportDesc->Name);
        HMODULE hImportedDll = LoadLibraryA(szDllName);

        if (!hImportedDll) {
            char errorBuf[256];
            StringCchPrintfA(errorBuf, sizeof(errorBuf), "Reassembler: Failed to load %s\n", szDllName);
            OutputDebugStringA(errorBuf);
            continue;
        }

        PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)(pNewImageBase + pImportDesc->FirstThunk);
        PIMAGE_THUNK_DATA pThunkOFT = NULL;
        if (pImportDesc->Characteristics != 0) {
            pThunkOFT = (PIMAGE_THUNK_DATA)(pNewImageBase + pImportDesc->Characteristics);
        }
        else {
            pThunkOFT = pThunkIAT;
        }

        for (; pThunkIAT->u1.Function != 0; ++pThunkIAT, ++pThunkOFT) {
            if (IMAGE_SNAP_BY_ORDINAL(pThunkOFT->u1.Ordinal)) {
                pThunkIAT->u1.Function = (UPTR)GetProcAddress(hImportedDll, (LPCSTR)IMAGE_ORDINAL(pThunkOFT->u1.Ordinal));
            }
            else {
                PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)(pNewImageBase + pThunkOFT->u1.AddressOfData);
                pThunkIAT->u1.Function = (UPTR)GetProcAddress(hImportedDll, pImportName->Name);
            }

            if (!pThunkIAT->u1.Function) {
                char errorBuf[512];
                StringCchPrintfA(errorBuf, sizeof(errorBuf), "Reassembler: Failed to resolve import %s from %s\n",
                    (pThunkOFT->u1.Ordinal & IMAGE_ORDINAL_FLAG) ? "ORDINAL" : (char*)((PIMAGE_IMPORT_BY_NAME)(pNewImageBase + pThunkOFT->u1.AddressOfData))->Name,
                    szDllName);
                OutputDebugStringA(errorBuf);
            }
        }
    }
    OutputDebugStringA("Reassembler: Imports resolved.\n");
}


VOID SetSectionProtections(PIMAGE_NT_HEADERS pNtHeaders, BYTE* pNewImageBase) {
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSection) {
        if (pSection->VirtualAddress == 0 || pSection->Misc.VirtualSize == 0) {
            continue;
        }

        DWORD oldProtect;
        DWORD newProtect = 0;
        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtect = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else {
            newProtect = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }

        if (newProtect == 0) newProtect = PAGE_READWRITE;

        if (!VirtualProtect(pNewImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, newProtect, &oldProtect)) {
            char errorBuf[256];
            StringCchPrintfA(errorBuf, sizeof(errorBuf), "Reassembler: Failed to set protection for section %.8s\n", pSection->Name);
            OutputDebugStringA(errorBuf);
        }
    }
    OutputDebugStringA("Reassembler: Memory protections set.\n");
}

VOID CallTlsCallbacks(PIMAGE_NT_HEADERS pNtHeaders, BYTE* pNewImageBase, DWORD fdwReason) {
    PIMAGE_DATA_DIRECTORY pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (pDataDir->VirtualAddress == 0) {
        return; 
    }

    PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)(pNewImageBase + pDataDir->VirtualAddress);

    PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTlsDir->AddressOfCallBacks;

    if (pCallback) {
        for (; *pCallback != NULL; ++pCallback) {
            (*pCallback)((LPVOID)pNewImageBase, fdwReason, NULL);
        }
    }
}

DWORD WINAPI ReassemblyThread(LPVOID lpParam) {
    HMODULE hOriginalModule = GetModuleHandle(NULL);
    if (!hOriginalModule) {
        OutputDebugStringA("Reassembler: Failed to get original EXE base address.\n");
        return 1;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hOriginalModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        OutputDebugStringA("Reassembler: Invalid DOS signature.\n");
        return 1;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hOriginalModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        OutputDebugStringA("Reassembler: Invalid NT signature.\n");
        return 1;
    }

    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    LPVOID pNewImageBase = VirtualAlloc((LPVOID)pNtHeaders->OptionalHeader.ImageBase, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pNewImageBase) {

        pNewImageBase = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!pNewImageBase) {
            OutputDebugStringA("Reassembler: Failed to allocate memory for the new image.\n");
            return 1;
        }
    }

    char debugMsg[256];
    StringCchPrintfA(debugMsg, sizeof(debugMsg), "Reassembler: Allocated new image at 0x%p (Size: 0x%I64X)\n", pNewImageBase, (ULONGLONG)imageSize);
    OutputDebugStringA(debugMsg);

    SIZE_T headersSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
    memcpy(pNewImageBase, hOriginalModule, headersSize);

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData > 0) {
            BYTE* pDest = (BYTE*)pNewImageBase + pSectionHeader->VirtualAddress;
            BYTE* pSrc = (BYTE*)hOriginalModule + pSectionHeader->PointerToRawData;
            memcpy(pDest, pSrc, pSectionHeader->SizeOfRawData);
        }
    }
    OutputDebugStringA("Reassembler: All sections copied.\n");

    ProcessImports(pNtHeaders, (BYTE*)pNewImageBase);

    UPTR oldBase = (UPTR)hOriginalModule;
    UPTR newBase = (UPTR)pNewImageBase;
    ProcessRelocations(pNtHeaders, (BYTE*)pNewImageBase, oldBase, newBase);

    SetSectionProtections(pNtHeaders, (BYTE*)pNewImageBase);

    CallTlsCallbacks(pNtHeaders, (BYTE*)pNewImageBase, DLL_PROCESS_ATTACH);
    OutputDebugStringA("Reassembler: TLS callbacks executed.\n");

    UPTR newEntryPoint = (UPTR)pNewImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    MainEntryPoint pEntryPoint = (MainEntryPoint)newEntryPoint;

    StringCchPrintfA(debugMsg, sizeof(debugMsg), "Reassembler: Jumping to new entry point at 0x%p\n", (void*)newEntryPoint);
    OutputDebugStringA(debugMsg);


    pEntryPoint((HINSTANCE)pNewImageBase, DLL_PROCESS_ATTACH, NULL);

    OutputDebugStringA("Reassembler: Entry point returned. Cleaning up.\n");


    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, ReassemblyThread, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}