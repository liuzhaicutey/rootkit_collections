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
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
        }
        found = Process32Next(snapshot, &processEntry);
    }

    CloseHandle(snapshot);
}

DWORD WINAPI MonitorProcess(LPVOID lpParam) {
    while (TRUE) {

        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        BOOL found = Process32First(snapshot, &processEntry);
        while (found) {
            if (wcscmp(processEntry.szExeFile, L"MonitorProcess.exe") != 0) { 
                TerminateProcessByName(processEntry.szExeFile);
                ShowPermissionError();
            }
            found = Process32Next(snapshot, &processEntry);
        }

        CloseHandle(snapshot);
        Sleep(1000);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, MonitorProcess, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
