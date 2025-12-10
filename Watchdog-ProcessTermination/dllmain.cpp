#include "pch.h"
#include <windows.h>
#include <tlhelp32.h>
#include <string>

void ShowPermissionError() {
    MessageBox(NULL, L"You don't have enough permission to run this process.", L"Permission Denied", MB_OK | MB_ICONERROR);
}

BOOL IsProcessRunning(const wchar_t* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BOOL found = Process32First(snapshot, &processEntry);
    while (found) {
        if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
            CloseHandle(snapshot);
            return TRUE;
        }
        found = Process32Next(snapshot, &processEntry);
    }

    CloseHandle(snapshot);
    return FALSE;
}

void TerminateProcessByName(const wchar_t* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    BOOL found = Process32First(snapshot, &processEntry);
    while (found) {
        if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
            if (hProcess != NULL) {
                if (!TerminateProcess(hProcess, 0)) {
                    ShowPermissionError(); 
                }
                CloseHandle(hProcess);
            }
            else {
                ShowPermissionError();
            }
        }
        found = Process32Next(snapshot, &processEntry);
    }

    CloseHandle(snapshot);
}

DWORD WINAPI MonitorProcess(LPVOID lpParam) {
    while (TRUE) {
        if (IsProcessRunning(L"Notepad.exe")) {
            TerminateProcessByName(L"Notepad.exe");
        }
        Sleep(1000);
    }
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule); 
        QueueUserWorkItem(MonitorProcess, NULL, WT_EXECUTEDEFAULT);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
