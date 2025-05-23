#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <sddl.h> // For ConvertSidToStringSid

using namespace std;

// Structure definitions
typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;

// Function prototype for NtQuerySystemInformation
extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif


BOOL Initialize();
BOOL SetPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL Process_List();
BOOL Process_Modules(DWORD dw_PID);
BOOL Process_Threads(DWORD dwOwnerPID);
BOOL RunningProcesses_details();
BOOL EnumerateProcessHandles(DWORD dwProcessId);

BOOL Process_List()
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriority_Class;


    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        _tprintf(TEXT("CreateToolhelp32Snapshot (of processes)"));
        return(FALSE);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        _tprintf(TEXT("Process32First")); // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }

    do
    {
        _tprintf(TEXT("\n\n................................................"));
        _tprintf(TEXT("\nProcess Name:  %s"), pe32.szExeFile);
        _tprintf(TEXT("\n.................................................."));
        dwPriority_Class = 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL)
            _tprintf(TEXT("OpenProcess!"));
        else
        {
            dwPriority_Class = GetPriorityClass(hProcess);
            if (!dwPriority_Class)
                _tprintf(TEXT("GetPriorityClass"));
            CloseHandle(hProcess);
        }

        _tprintf(TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID);
        _tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
        _tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
        _tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
        _tprintf(TEXT("\n  Size     = %d"), pe32.dwSize);
        _tprintf(TEXT("\n  Usage     = %d"), pe32.cntUsage);
        _tprintf(TEXT("\n  Flags     = %d"), pe32.dwFlags);
        if (dwPriority_Class)
            _tprintf(TEXT("\n  Priority class    = %d"), dwPriority_Class);

        Process_Modules(pe32.th32ProcessID);
        Process_Threads(pe32.th32ProcessID);

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return(TRUE);
}


BOOL Process_Modules(DWORD dw_PID)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 ME32;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dw_PID);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        _tprintf(TEXT("CreateToolhelp32Snapshot (of modules)"));
        return(FALSE);
    }

    ME32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hModuleSnap, &ME32))
    {
        _tprintf(TEXT("Module32First"));  // show cause of failure
        CloseHandle(hModuleSnap);           // clean the snapshot object
        return(FALSE);
    }
    do
    {
        printf("\nProcess ID: %u\n", dw_PID);
        _tprintf(TEXT("\n\n   Module Name:     %s"), ME32.szModule);
        _tprintf(TEXT("\n     Executable     = %s"), ME32.szExePath);
        _tprintf(TEXT("\n     Process ID     = 0x%08X"), ME32.th32ProcessID);
        _tprintf(TEXT("\n     Module ID      = %d"), ME32.th32ModuleID);
        _tprintf(TEXT("\n     Base size      = %d"), ME32.modBaseSize);

    } while (Module32Next(hModuleSnap, &ME32));

    CloseHandle(hModuleSnap);
    return(TRUE);
}

BOOL Process_Threads(DWORD dwOwnerPID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return FALSE;

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        CloseHandle(hThreadSnap); // Clean the snapshot object
        return FALSE;
    }

    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread == NULL)
            {
                _tprintf(TEXT("Error: Could not open thread. GetLastError: %d\n"), GetLastError());
            }
            else
            {
                // Basic thread information
                _tprintf(TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
                _tprintf(TEXT("\n     Base priority  = %d"), te32.tpBasePri);
                _tprintf(TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);

                // Getting thread times
                FILETIME ftCreation, ftExit, ftKernel, ftUser;
                if (GetThreadTimes(hThread, &ftCreation, &ftExit, &ftKernel, &ftUser))
                {
                    SYSTEMTIME stCreation;
                    FileTimeToSystemTime(&ftCreation, &stCreation);
                    _tprintf(TEXT("\n     Created: %02d/%02d/%d %02d:%02d:%02d"), stCreation.wMonth, stCreation.wDay, stCreation.wYear, stCreation.wHour, stCreation.wMinute, stCreation.wSecond);
                }

                // Additional detailed queries can be placed here, but may require more complex APIs

                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return TRUE;
}

BOOL EnumerateProcessHandles(DWORD dwProcessId) {
    // Load ntdll.dll
    HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
    if (hNtdll == NULL) {
        cout << "Failed to load ntdll.dll" << endl;
        return FALSE;
    }

    // Get the address of NtQuerySystemInformation
    typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL) {
        cout << "Failed to get the address of NtQuerySystemInformation" << endl;
        FreeLibrary(hNtdll);
        return FALSE;
    }

    ULONG handleInfoSize = 0x10000;
    SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)malloc(handleInfoSize);

    // Call NtQuerySystemInformation using the function pointer
    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, &handleInfoSize);
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        SYSTEM_HANDLE_INFORMATION* newHandleInfo = (SYSTEM_HANDLE_INFORMATION*)realloc(handleInfo, handleInfoSize * 2);
        if (newHandleInfo == NULL) {
            cout << "Memory reallocation failed." << endl;
            free(handleInfo);
            FreeLibrary(hNtdll);
            return FALSE;
        }
        handleInfo = newHandleInfo;
        status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize * 2, &handleInfoSize);
    }

    if (status != STATUS_SUCCESS) {
        cout << "NtQuerySystemInformation failed" << endl;
        free(handleInfo);
        FreeLibrary(hNtdll);
        return FALSE;
    }

    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        if (handle.ProcessId == dwProcessId) {
            cout << "Handle: " << handle.Handle << " Object: " << handle.Object << " Access: " << handle.GrantedAccess << endl;
        }
    }

    free(handleInfo);
    FreeLibrary(hNtdll);
    return TRUE;
}

BOOL Initialize() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        cout << "Failed to open process token. Error: " << GetLastError() << endl;
        return FALSE;
    }

    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        cout << "Failed to set privilege. Error: " << GetLastError() << endl;
        CloseHandle(hToken);  // Ensure the handle is closed even if setting privilege fails
        return FALSE;
    }

    CloseHandle(hToken);  // Close the handle after it's no longer needed
    return TRUE;
}

BOOL SetPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        cout << "LookupPrivilegeValue error: " << GetLastError() << endl;
        return FALSE;  // No need to close hToken here, it's handled in Initialize
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        cout << "AdjustTokenPrivileges error: " << GetLastError() << endl;
        return FALSE;  // No need to close hToken here, it's handled in Initialize
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        cout << "The token does not have the specified privilege. \n";
        return FALSE;  // No need to close hToken here, it's handled in Initialize
    }

    return TRUE;
}

BOOL RunningProcesses_details() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Open a file to write the CSV data
    ofstream outputFile("processes.csv");
    outputFile << "PID,Process Name,Thread Count,PPID,Priority Base,Executable Path,Working Set Size,Pagefile Usage,User Context\n";

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        cout << "CreateToolhelp32Snapshot failed." << endl;
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        cout << "Process32First failed." << endl;
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    do {
        outputFile << pe32.th32ProcessID << ",";
        outputFile << "\"" << pe32.szExeFile << "\",";
        outputFile << pe32.cntThreads << ",";
        outputFile << pe32.th32ParentProcessID << ",";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            DWORD priority = GetPriorityClass(hProcess);
            outputFile << priority << ",";

            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                outputFile << "\"" << szProcessName << "\",";
            }

            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                outputFile << pmc.WorkingSetSize << ",";
                outputFile << pmc.PagefileUsage << ",";
            }

            // Getting user context (simplified and may need adjustments)
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                DWORD dwSize = 0;
                GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
                TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(new BYTE[dwSize]);

                if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                    LPTSTR StringSid;
                    if (ConvertSidToStringSid(pTokenUser->User.Sid, &StringSid)) {
                        outputFile << "\"" << StringSid << "\"";
                        LocalFree(StringSid);
                    }
                }

                delete[] pTokenUser;
                CloseHandle(hToken);
            }

            CloseHandle(hProcess);
        }

        outputFile << "\n";

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    outputFile.close();
    return TRUE;
}


int main(void)
{
    if (!Initialize()) {
        cout << "Initialization failed." << endl;
        return 1;
    }
    system("Color 0A");
    cout << "|===============================================================================|" << endl;
    cout << "|============================= John A. ===============================|" << endl;
    cout << "|===============================================================================|" << endl;
    cout << "|                             Program Description                               |" << endl;
    cout << "|                    To View Processes Details and Modules                      |" << endl;
    cout << "|===============================================================================|" << endl;
    cout << "|============================= John 0070 ==================================|" << endl;
    cout << "|===============================================================================|" << endl;
    cout << "" << endl;
    cout << "" << endl;
    cout << "" << endl;
    cout << "" << endl;
    cout << "Select any one of the Option listed below" << endl;
    cout << "" << endl;
    cout << "" << endl;
    cout << "1- To list all the running Processes and Associated  Modules" << endl;
    cout << "2- List Processes and Threads" << endl;
    cout << "" << endl;
    cout << "" << endl;

    char option;
    cout << "Enter Option: ";
    cin >> option;


    switch (option) {
    case '1':
        cout << "+++++++++" << endl;
        cout << "" << endl;
        Process_List();
        break;
    case '2':
        cout << "++++++++" << endl;
        cout << "" << endl;
        RunningProcesses_details();
        break;
    default:
        cout << "Invalid Option" << endl;
        break;
    }

    return 0;
}