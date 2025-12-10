#include "pch.h"
#include <windows.h>
#include <tlhelp32.h>
#include <set>
#include <string>
#include <fstream>

#define LOG_PATH L"C:\\process_monitor_log.txt" // Debugger. Remove if not necessary.


void Log(const std::wstring& msg)
{
    std::wofstream file(LOG_PATH, std::ios::app);
    if (file.is_open())
        file << msg << std::endl;
}


BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        Log(L"OpenProcessToken failed");
        return FALSE;
    }

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

    CloseHandle(hToken);

    if (GetLastError() != ERROR_SUCCESS)
    {
        Log(L"AdjustTokenPrivileges failed");
        return FALSE;
    }

    Log(L"SeDebugPrivilege enabled");
    return TRUE;
}


std::set<DWORD> GetProcessIDs()
{
    std::set<DWORD> result;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        Log(L"CreateToolhelp32Snapshot failed");
        return result;
    }

    if (Process32First(hSnap, &pe32))
    {
        do {
            result.insert(pe32.th32ProcessID);
        } while (Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return result;
}


void KillPID(DWORD pid)
{
    if (pid == 0)
        return;

    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc)
    {
        Log(L"OpenProcess failed for PID " + std::to_wstring(pid));
        return;
    }

    if (!TerminateProcess(hProc, 0))
        Log(L"TerminateProcess FAILED for PID " + std::to_wstring(pid));
    else
        Log(L"Process terminated: PID " + std::to_wstring(pid));

    CloseHandle(hProc);
}


DWORD WINAPI MonitorThread(LPVOID)
{
    Log(L"MonitorThread started");


    std::set<DWORD> knownPIDs = GetProcessIDs();

    while (true)
    {
        std::set<DWORD> current = GetProcessIDs();


        for (DWORD pid : current)
        {
            if (knownPIDs.count(pid) == 0)
            {
                Log(L"New process detected: PID " + std::to_wstring(pid));
                KillPID(pid);
            }
        }

        knownPIDs = current;

        Sleep(500);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        EnableDebugPrivilege();

        CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);

        break;
    }
    return TRUE;
}
