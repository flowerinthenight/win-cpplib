/*
* Copyright(c) 2016 Chew Esmero
* All rights reserved.
*/

#include "stdafx.h"
#include "../include/libcore.h"
#include <Windows.h>
#include <atlbase.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <tchar.h>
#include <comdef.h>
#include <Psapi.h>
#include <WtsApi32.h>
#include <powerbase.h>
#include <UserEnv.h>
#include <tlhelp32.h>
#include <fstream>
#include <iomanip>
#include <string>
#include <bitset>
using namespace std;
#include <comdef.h>
#include <stdarg.h>
#include <wchar.h>
#include <varargs.h>
#include <UIAnimation.h>
#include <UIAutomationClient.h>
#include <appmodel.h>
#include <evntprov.h>
#include <evntrace.h>
#include <VersionHelpers.h>
#include <PathCch.h>
#include "../etw/jysdk.h"
#include "../include/sdkdefines.h"
#include "../include/sdktrace.h"
#include <strsafe.h>
using namespace ATL;

#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "UserEnv.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "pathcch.lib")

_declspec(dllexport) BOOL IsWow64()
{
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    BOOL bIsWow64 = FALSE;

    if (hKernel32)
    {
        fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hKernel32, "IsWow64Process");

        if (NULL != fnIsWow64Process)
        {
            if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
            {
                ;
            }
        }
    }

    return bIsWow64;
}

_declspec(dllexport) void CreateGlobalEvent(HANDLE *pHandle, TCHAR *pszName, BOOL bManualReset)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWritePointerInfo(M, FL, FN, L"HandlePtr", pHandle);
    EventWriteWideStrInfo(M, FL, FN, L"Name", pszName);
    EventWriteBoolInfo(M, FL, FN, L"Manual?", bManualReset);

    SECURITY_ATTRIBUTES secAttr;
    SECURITY_DESCRIPTOR sedDesc;
    InitializeSecurityDescriptor(&sedDesc, SECURITY_DESCRIPTOR_REVISION);

#pragma warning(suppress: 6248)
    SetSecurityDescriptorDacl(&sedDesc, TRUE, NULL, FALSE);
    secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    secAttr.bInheritHandle = FALSE;
    secAttr.lpSecurityDescriptor = &sedDesc;

    *pHandle = CreateEvent(&secAttr, bManualReset, FALSE, pszName);

    EventWriteHexInfo(M, FL, FN, L"OutHandle", (UINT)*pHandle);

    EventWriteFunctionExit(M, FL, FN);
}

_declspec(dllexport) void CreateGlobalMutex(HANDLE *pHandle, TCHAR *pszName)
{
    EventWriteFunctionEntry(M, FL, FN);

    SECURITY_ATTRIBUTES secAttr;
    SECURITY_DESCRIPTOR sedDesc;
    InitializeSecurityDescriptor(&sedDesc, SECURITY_DESCRIPTOR_REVISION);

#pragma warning(suppress: 6248)
    SetSecurityDescriptorDacl(&sedDesc, TRUE, NULL, FALSE);
    secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    secAttr.bInheritHandle = FALSE;
    secAttr.lpSecurityDescriptor = &sedDesc;

    *pHandle = CreateMutex(&secAttr, FALSE, pszName);

    EventWriteWideStrInfo(M, FL, FN, L"Name", pszName);
    EventWriteHexInfo(M, FL, FN, L"OutHandle", (UINT)*pHandle);

    EventWriteFunctionExit(M, FL, FN);
}

_declspec(dllexport) void SetDoubleWordAtomic(LPCRITICAL_SECTION pcs, LPDWORD pDest, DWORD dwValue)
{
    EnterCriticalSection(pcs);
    *pDest = dwValue;
    LeaveCriticalSection(pcs);
}

_declspec(dllexport) void PrintComError(HRESULT hr, TCHAR *pszMsg)
{
    _com_error err(hr);
    LPCTSTR szErrorText = err.ErrorMessage();
    TCHAR szDump[MAX_PATH];
    StringCchPrintf(szDump, 100, L"%s: %s (0x%x)\n", pszMsg, szErrorText, hr);
    OutputDebugString(szDump);
}

_declspec(dllexport) HRESULT GetComTextError(HRESULT hr, wchar_t *pszOut, DWORD *pcchLen)
{
    if (!pcchLen) return E_INVALIDARG;
    if (*pcchLen < 1) return E_INVALIDARG;

    TCHAR szTrace[MAX_PATH];
    _com_error err(hr);
    LPCTSTR szErrorText = err.ErrorMessage();

    StringCchPrintf(szTrace, *pcchLen, L"%s (0x%x)", szErrorText, hr);

    return StringCchCopy(pszOut, *pcchLen, szTrace);
}

_declspec(dllexport) void DumpLastError(TCHAR *pszExtra)
{
    LPVOID lpSysErrorBuff;
    LPVOID lpDisplayBuf;
    DWORD dwError = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpSysErrorBuff,
        0,
        NULL);

    lpDisplayBuf = (LPVOID)LocalAlloc(
        LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpSysErrorBuff) +
            lstrlen((LPCTSTR)pszExtra) + 40) *
        sizeof(TCHAR));

    if (lpDisplayBuf)
    {
        StringCchPrintf(
            (LPTSTR)lpDisplayBuf,
            LocalSize(lpDisplayBuf) / sizeof(TCHAR),
            TEXT("[%d_LastError (%s)] >>> %d = %s"),
            GetCurrentThreadId(),
            pszExtra,
            dwError,
            (wchar_t*)lpSysErrorBuff);

        OutputDebugString((LPCTSTR)lpDisplayBuf);

        LocalFree(lpDisplayBuf);
        LocalFree(lpSysErrorBuff);
    }
    else
    {
        wchar_t szDump[MAX_PATH];
        StringCchPrintf(szDump, MAX_PATH, L"LastError: %d (???)", dwError);
        OutputDebugString(szDump);
    }
}

_declspec(dllexport) void GetLastErrorDescription(DWORD dwLastError, wchar_t *pszOut, DWORD cchLen)
{
    LPVOID lpSysErrorBuff;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpSysErrorBuff,
        0,
        NULL);

    if (lpSysErrorBuff)
    {
        StringCchCopy(pszOut, cchLen, (wchar_t*)lpSysErrorBuff);
        LocalFree(lpSysErrorBuff);
    }
    else
    {
        if (pszOut)
        {
            pszOut[0] = L'\0';
        }
    }
}

_declspec(dllexport) void HandleCleanup(HANDLE *pHandle)
{
    if (*pHandle)
    {
        EventWriteHexInfo(M, FL, FN, L"Handle", (UINT)*pHandle);
        CloseHandle(*pHandle);
        *pHandle = NULL;
    }
}

_declspec(dllexport) BOOL EnableTokenPrivilege(LPTSTR szPrivilege)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"Privilege", szPrivilege);

    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    DWORD dwSize;

    ZeroMemory(&tp, sizeof(tp));

    tp.PrivilegeCount = 1;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        EventWriteLastError(M, FL, FN, L"OpenProcessToken", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, szPrivilege, &tp.Privileges[0].Luid))
    {
        EventWriteLastError(M, FL, FN, L"LookupPrivilegeValue", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize))
    {
        EventWriteLastError(M, FL, FN, L"AdjustTokenPrivileges", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    EventWriteFunctionExit(M, FL, FN);

    return TRUE;
}

//
// Must be admin to call this function. Also, sometimes you need to change the calling process'
// current directory for this to be successful.
//
_declspec(dllexport) BOOL StartSystemUserProcess(
    wchar_t *pszCmd,
    wchar_t *pszParam,
    WINSTA0_DESKTOP winstaDesktop,
    DWORD *pdwExitCode,
    BOOL bWaitTerm,
    DWORD dwWaitMs)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"Command", pszCmd);
    EventWriteWideStrInfo(M, FL, FN, L"Param", pszParam);
    EventWriteNumberInfo(M, FL, FN, L"Desktop", winstaDesktop);
    EventWritePointerInfo(M, FL, FN, L"ExitCodePtr", pdwExitCode);
    EventWriteBoolInfo(M, FL, FN, L"WaitTerm?", bWaitTerm);
    EventWriteNumberInfo(M, FL, FN, L"WaitMs", dwWaitMs);

    wchar_t szCmd[MAX_PATH];
    DWORD dwDirSize = sizeof(szCmd);
    STARTUPINFO si;
    BOOL bResult = FALSE;
    BOOL bReturn = FALSE;
    DWORD dwSessionId = 0xf, winlogonPid = 0xf;
    HANDLE hUserToken, hUserTokenDup, hPToken, hProcess;
    DWORD dwCreationFlags;
    PROCESSENTRY32 procEntry;
    PROCESS_INFORMATION pi;

    StringCchPrintf(szCmd, MAX_PATH, L"\"%s\" %s", pszCmd, pszParam);

    EventWriteWideStrInfo(M, FL, FN, L"Command", szCmd);

    dwSessionId = WTSGetActiveConsoleSessionId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;

    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &procEntry)) return FALSE;

    do
    {
        if (_wcsicmp(procEntry.szExeFile, L"winlogon.exe") == 0)
        {
            //
            // We found a winlogon process...make sure it's running in the console session.
            //
            DWORD winlogonSessId = 0;

            if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId)
                && winlogonSessId == dwSessionId)
            {
                winlogonPid = procEntry.th32ProcessID;
                break;
            }
        }
    } while (Process32Next(hSnap, &procEntry));

    WTSQueryUserToken(dwSessionId, &hUserToken);
    dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    switch (winstaDesktop)
    {
    case WINSTA0_DEFAULT:
    {
        si.lpDesktop = L"winsta0\\default";
        break;
    }

    case WINSTA0_WINLOGON:
    {
        si.lpDesktop = L"winsta0\\WinLogon";
        break;
    }

    default:
    {
        si.lpDesktop = L"winsta0\\default";
        break;
    }
    }

    ZeroMemory(&pi, sizeof(pi));
    TOKEN_PRIVILEGES tp;
    LUID luid;

    hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);

    bResult = OpenProcessToken(
        hProcess,
        TOKEN_ADJUST_PRIVILEGES |
        TOKEN_QUERY |
        TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY |
        TOKEN_ADJUST_SESSIONID |
        TOKEN_READ |
        TOKEN_WRITE,
        &hPToken);

    if (!bResult)
    {
        EventWriteLastError(M, FL, FN, L"OpenProcessToken", GetLastError());
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        EventWriteLastError(M, FL, FN, L"LookupPrivilegeValue", GetLastError());
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserTokenDup);
    SetTokenInformation(hUserTokenDup, TokenSessionId, (void*)dwSessionId, sizeof(DWORD));

    bResult = AdjustTokenPrivileges(
        hUserTokenDup,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        NULL);

    if (!bResult)
    {
        EventWriteLastError(M, FL, FN, L"AdjustTokenPrivileges", GetLastError());
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        EventWriteErrorW(M, FL, FN, L"ERROR_NOT_ALL_ASSIGNED: Token does not have the privilege.");
    }

    LPVOID pEnv = NULL;

    if (CreateEnvironmentBlock(&pEnv, hUserTokenDup, TRUE))
    {
        dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
    }
    else
    {
        pEnv = NULL;
    }

    //
    // Launch the process in the client's logon session.
    //
    bResult = CreateProcessAsUser(
        hUserTokenDup,
        NULL,
        szCmd,
        NULL,
        NULL,
        FALSE,
        dwCreationFlags,
        pEnv,
        NULL,
        &si,
        &pi);

    bReturn = bResult ? TRUE : FALSE;

    if (bWaitTerm == TRUE)
    {
        if (WaitForSingleObject(pi.hProcess, dwWaitMs) == WAIT_OBJECT_0)
        {
            if (pdwExitCode)
            {
                GetExitCodeProcess(pi.hProcess, pdwExitCode);
            }
        }
    }

    HandleCleanup(&pi.hThread);
    HandleCleanup(&pi.hProcess);
    HandleCleanup(&hProcess);
    HandleCleanup(&hUserToken);
    HandleCleanup(&hUserTokenDup);
    HandleCleanup(&hPToken);

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL IsServiceActive(wchar_t *pszName)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"Service", pszName);

    BOOL bReturn = FALSE;
    BOOL bRet;
    SC_HANDLE hManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS sStatus;

    while (TRUE)
    {
        hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (hManager == NULL) break;

        hService = OpenService(hManager, pszName, SERVICE_QUERY_STATUS);
        if (hService == NULL) break;

        ZeroMemory(&sStatus, sizeof(SERVICE_STATUS));

        bRet = QueryServiceStatus(hService, &sStatus);
        if (bRet == FALSE) break;

        if (sStatus.dwCurrentState == SERVICE_RUNNING)
        {
            bReturn = TRUE;
        }

        break;
    }

    if (hService) CloseServiceHandle(hService);
    if (hManager) CloseServiceHandle(hManager);

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL IsProcessInRunState(wchar_t *pszProcessName, DWORD *pdwProcessId)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"ProcessName", pszProcessName);
    EventWritePointerInfo(M, FL, FN, L"PidPtr", pdwProcessId);

    BOOL bReturn = FALSE;
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    DWORD cProcesses;

    if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        cProcesses = cbNeeded / sizeof(DWORD);

        for (unsigned int i = 0; i < cProcesses; i++)
        {
            if (aProcesses[i] != 0)
            {
                TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

                if (hProcess)
                {
                    HMODULE hMod; cbNeeded;

                    if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL))
                    {
                        GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                    }

                    CloseHandle(hProcess);
                }

                if (_tcsicmp(szProcessName, pszProcessName) == 0)
                {
                    if (pdwProcessId != NULL)
                    {
                        *pdwProcessId = aProcesses[i];
                    }

                    bReturn = TRUE;
                    break;
                }
            }
        }
    }

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL SendCtrlCodeToService(wchar_t *pszSvcName, DWORD dwCtrl)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"Service", pszSvcName);
    EventWriteNumberInfo(M, FL, FN, L"Control", dwCtrl);

    TCHAR szCommand[MAX_PATH];
    TCHAR szDirectory[MAX_PATH];
    TCHAR szArgs[MAX_PATH];
    DWORD dwStatus;

    UINT size = GetWindowsDirectory(szDirectory, MAX_PATH);
    if (size == 0) return false;

    StringCchCat(szDirectory, MAX_PATH, TEXT("\\System32"));
    StringCchPrintf(szCommand, MAX_PATH, TEXT("%s\\sc.exe"), szDirectory);

    StringCchPrintf(szArgs, MAX_PATH, L"control %s %d", pszSvcName, dwCtrl);

    BOOL bReturn = HiddenExecute(szCommand, szDirectory, szArgs, &dwStatus, TRUE, 30000);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL NormalExecute(
    wchar_t *pszFile,
    wchar_t *pszDirectory,
    wchar_t *pszParams,
    DWORD *pdwExitCode,
    BOOL bWaitTerm,
    DWORD dwWaitMs)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"File", pszFile);
    EventWriteWideStrInfo(M, FL, FN, L"Directory", pszDirectory);
    EventWriteWideStrInfo(M, FL, FN, L"Param", pszParams);
    EventWritePointerInfo(M, FL, FN, L"ExitCodePtr", pdwExitCode);
    EventWriteBoolInfo(M, FL, FN, L"WaitTerm?", bWaitTerm);
    EventWriteNumberInfo(M, FL, FN, L"WaitMs", dwWaitMs);

    PROCESS_INFORMATION pi;
    STARTUPINFO si;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_FORCEOFFFEEDBACK;
    si.wShowWindow = SW_SHOWNORMAL;
    TCHAR szCmdFile[MAX_PATH];

    if (pszFile[0] == L'\"')
    {
        StringCchPrintf(szCmdFile, MAX_PATH, L"%s", pszFile);
    }
    else
    {
        StringCchPrintf(szCmdFile, MAX_PATH, L"\"%s\"", pszFile);
    }

    StringCchCat(szCmdFile, MAX_PATH, L" ");
    StringCchCat(szCmdFile, MAX_PATH, pszParams);

    if (CreateProcess(
        NULL,
        szCmdFile,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
        NULL,
        pszDirectory,
        &si,
        &pi) == 0)
    {
        EventWriteLastError(M, FL, FN, L"CreateProcess", GetLastError());
        return FALSE;
    }

    CloseHandle(pi.hThread);

    if (bWaitTerm == TRUE)
    {
        if (WaitForSingleObject(pi.hProcess, dwWaitMs) != WAIT_OBJECT_0)
        {
            EventWriteLastError(M, FL, FN, L"WaitForSingleObject", GetLastError());
            CloseHandle(pi.hProcess);
            return FALSE;
        }

        GetExitCodeProcess(pi.hProcess, pdwExitCode);
    }

    CloseHandle(pi.hProcess);

    EventWriteFunctionExit(M, FL, FN);

    return TRUE;
}

//
// Derived from NormalExecute function. Adjacent means the function assumes that the provided filename 'pszFile' (should not include
// directory location details, just filename) is in the same location as the process that loads this library.
//
_declspec(dllexport) BOOL NormalExecuteSubsys(wchar_t *pszFile, wchar_t *pszParams, DWORD *pdwExitCode, BOOL bWaitTerm, DWORD dwWaitMs)
{
    wchar_t szCmd[MAX_PATH] = { 0 };
    wchar_t szDir[MAX_PATH] = { 0 };
    DWORD cchLen = MAX_PATH;

    GetCurrentProcessPath(szDir, &cchLen);

    StringCchPrintf(szCmd, MAX_PATH, L"%s\\%s", szDir, pszFile);

    return NormalExecute(szCmd, szDir, pszParams, pdwExitCode, bWaitTerm, dwWaitMs);
}

_declspec(dllexport) BOOL HiddenExecute(
    wchar_t *pszFile,
    wchar_t *pszDirectory,
    wchar_t *pszParams,
    DWORD *pdwExitCode,
    BOOL bWaitTerm,
    DWORD dwWaitMs)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"File", pszFile);
    EventWriteWideStrInfo(M, FL, FN, L"Directory", pszDirectory);
    EventWriteWideStrInfo(M, FL, FN, L"Param", pszParams);
    EventWritePointerInfo(M, FL, FN, L"ExitCodePtr", pdwExitCode);
    EventWriteBoolInfo(M, FL, FN, L"WaitTerm?", bWaitTerm);
    EventWriteNumberInfo(M, FL, FN, L"WaitMs", dwWaitMs);

    PROCESS_INFORMATION pi;
    STARTUPINFO si;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_FORCEOFFFEEDBACK;
    si.wShowWindow = SW_HIDE;
    TCHAR szCmdFile[MAX_PATH];

    if (pszFile[0] == L'\"')
    {
        StringCchPrintf(szCmdFile, MAX_PATH, L"%s", pszFile);
    }
    else
    {
        StringCchPrintf(szCmdFile, MAX_PATH, L"\"%s\"", pszFile);
    }

    StringCchCat(szCmdFile, MAX_PATH, L" ");
    StringCchCat(szCmdFile, MAX_PATH, pszParams);

    if (CreateProcess(
        NULL,
        szCmdFile,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS,
        NULL,
        pszDirectory,
        &si,
        &pi) == 0)
    {
        EventWriteLastError(M, FL, FN, L"CreateProcess", GetLastError());
        return FALSE;
    }

    CloseHandle(pi.hThread);

    if (bWaitTerm == TRUE)
    {
        if (WaitForSingleObject(pi.hProcess, dwWaitMs) != WAIT_OBJECT_0)
        {
            EventWriteLastError(M, FL, FN, L"WaitForSingleObject", GetLastError());
            CloseHandle(pi.hProcess);
            return FALSE;
        }

        GetExitCodeProcess(pi.hProcess, pdwExitCode);
    }

    CloseHandle(pi.hProcess);

    EventWriteFunctionExit(M, FL, FN);

    return TRUE;
}

//
// Derived from HiddenExecute function. Adjacent means the function assumes that the provided filename 'pszFile' (should not include
// directory location details, just filename) is in the same location as the process that loads this library.
//
_declspec(dllexport) BOOL HiddenExecuteSubsys(wchar_t *pszFile, wchar_t *pszParams, DWORD *pdwExitCode, BOOL bWaitTerm, DWORD dwWaitMs)
{
    wchar_t szCmd[MAX_PATH] = { 0 };
    wchar_t szDir[MAX_PATH] = { 0 };
    DWORD cchLen = MAX_PATH;

    GetCurrentProcessPath(szDir, &cchLen);

    StringCchPrintf(szCmd, MAX_PATH, L"%s\\%s", szDir, pszFile);

    return HiddenExecute(szCmd, szDir, pszParams, pdwExitCode, bWaitTerm, dwWaitMs);
}

//
// Run internal DLL functions using rundll32.exe host.
//
_declspec(dllexport) BOOL ProxyRunDll32(
    wchar_t *pszDll,
    wchar_t *pszEntry,
    wchar_t *pszParams,
    DWORD *pdwExitCode,
    BOOL bWaitTerm,
    DWORD dwWaitMs)
{
    wchar_t szDir[MAX_PATH] = { 0 };
    wchar_t szCmd[MAX_PATH] = { 0 };
    wchar_t szParam[MAX_PATH] = { 0 };

    EventWriteWideStrInfo(M, FL, FN, L"DllName", pszDll);
    EventWriteWideStrInfo(M, FL, FN, L"Entry", pszEntry);

    if (pszDll[0] == L'\"')
    {
        StringCchPrintf(szParam, MAX_PATH, L"%s,%s %s", pszDll, pszEntry, pszParams);
    }
    else
    {
        StringCchPrintf(szParam, MAX_PATH, L"\"%s\",%s %s", pszDll, pszEntry, pszParams);
    }

    EventWriteWideStrInfo(M, FL, FN, L"Params", szParam);

    GetSystemDirectory(szDir, MAX_PATH);
    GetSystemDirectory(szCmd, MAX_PATH);
    StringCchCat(szCmd, MAX_PATH, L"\\rundll32.exe");

    return HiddenExecute(szCmd, szDir, szParam, pdwExitCode, bWaitTerm, dwWaitMs);
}

_declspec(dllexport) BOOL IsDllLoaded(wchar_t *pszDllName, PDWORD pdwProcessId)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"DllName", pszDllName);
    EventWritePointerInfo(M, FL, FN, L"PidPtr", pdwProcessId);

    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe32;
    BOOL bRun = FALSE;

    if (!EnableTokenPrivilege(SE_DEBUG_NAME))
    {
        EventWriteLastError(M, FL, FN, L"EnableTokenPrivilege", GetLastError());
        return FALSE;
    }

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        EventWriteErrorW(M, FL, FN, L"INVALID_HANDLE_VALUE: CreateToolhelp32Snapshot");
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        EventWriteLastError(M, FL, FN, L"Process32First", GetLastError());
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    do
    {
        //
        // Start enumerating each process's modules.
        //
        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        MODULEENTRY32 me32;

        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);

        if (hModuleSnap == INVALID_HANDLE_VALUE)
        {
            EventWriteErrorW(M, FL, FN, L"INVALID_HANDLE_VALUE: CreateToolhelp32Snapshot");
            continue;
        }

        me32.dwSize = sizeof(MODULEENTRY32);

        if (!Module32First(hModuleSnap, &me32))
        {
            EventWriteLastError(M, FL, FN, L"Module32First", GetLastError());
            CloseHandle(hModuleSnap);
            return FALSE;
        }

        do
        {
            wstring wstr(me32.szExePath);
            size_t found = wstr.find(pszDllName);

            if (found != wstring::npos)
            {
                *pdwProcessId = pe32.th32ProcessID;
                bRun = TRUE;
                break;
            }
        } while (Module32Next(hModuleSnap, &me32));

        CloseHandle(hModuleSnap);

        if (bRun)
        {
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    EventWriteBoolInfo(M, FL, FN, L"bRun", bRun);

    EventWriteFunctionExit(M, FL, FN);

    return bRun;
}

_declspec(dllexport) LSTATUS IsDllLoaded2(wchar_t *pszDllName, PDWORD pdwPidList, PDWORD pcbCount)
{
    EventWriteWideStrInfo(M, FL, FN, L"DllName", pszDllName);
    EventWritePointerInfo(M, FL, FN, L"PidList", pdwPidList);

    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
    LSTATUS lStatus = ERROR_UNIDENTIFIED_ERROR;
    PROCESSENTRY32 pe32;
    DWORD *pdwList = NULL;
    DWORD *pdwList2 = NULL;
    DWORD cbCount = 0;

    if (!EnableTokenPrivilege(SE_DEBUG_NAME))
    {
        EventWriteLastError(M, FL, FN, L"EnableTokenPrivilege", GetLastError());
        return FALSE;
    }

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        EventWriteErrorW(M, FL, FN, L"INVALID_HANDLE_VALUE: CreateToolhelp32Snapshot");
        return FALSE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        EventWriteLastError(M, FL, FN, L"Process32First", GetLastError());
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    do
    {
        //
        // Start enumerating each process's modules.
        //
        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        MODULEENTRY32 me32;

        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);

        if (hModuleSnap == INVALID_HANDLE_VALUE)
        {
            EventWriteErrorW(M, FL, FN, L"INVALID_HANDLE_VALUE: CreateToolhelp32Snapshot");
            continue;
        }

        me32.dwSize = sizeof(MODULEENTRY32);

        if (!Module32First(hModuleSnap, &me32))
        {
            EventWriteLastError(M, FL, FN, L"Module32First", GetLastError());
            CloseHandle(hModuleSnap);
            return FALSE;
        }

        do
        {
            wstring wstr(me32.szExePath);
            size_t found = wstr.find(pszDllName);

            if (found != wstring::npos)
            {
                cbCount++;

                if (cbCount == 1)
                {
                    pdwList = (DWORD*)malloc(sizeof(DWORD));
                    pdwList[cbCount - 1] = pe32.th32ProcessID;
                }
                else
                {
                    pdwList2 = (DWORD*)realloc(pdwList, cbCount * sizeof(DWORD));

                    if (pdwList2)
                    {
                        pdwList = pdwList2;
                        pdwList[cbCount - 1] = pe32.th32ProcessID;
                    }
                }
            }
        } while (Module32Next(hModuleSnap, &me32));

        CloseHandle(hModuleSnap);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    if (pcbCount)
    {
        if (*pcbCount < cbCount)
        {
            lStatus = ERROR_MORE_DATA;
            *pcbCount = cbCount;
        }
        else
        {
            if (pdwPidList)
            {
                for (ULONG i = 0; i < cbCount; i++)
                {
                    pdwPidList[i] = pdwList[i];
                }

                lStatus = ERROR_SUCCESS;
            }
            else
            {
                lStatus = ERROR_BAD_ARGUMENTS;
            }
        }
    }

    return lStatus;
}

_declspec(dllexport) BOOL SystemIsConnectedStandbyCapable()
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;
    SYSTEM_POWER_CAPABILITIES spc;
    ZeroMemory(&spc, sizeof(SYSTEM_POWER_CAPABILITIES));

    LONG lStatus = CallNtPowerInformation(
        SystemPowerCapabilities,
        NULL,
        0,
        &spc,
        sizeof(SYSTEM_POWER_CAPABILITIES));

    if (lStatus == ERROR_SUCCESS)
    {
        bReturn = (BOOL)spc.AoAc;
    }

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) void DwordToBitStr(DWORD dwValue, DWORD cchLen, wchar_t *pszBits)
{
    bitset<32> bit((ULONGLONG)dwValue);
    wstring wstr = bit.to_string<wchar_t>();
    StringCchPrintf(pszBits, cchLen, L"%s", wstr.c_str());
}

_declspec(dllexport) BOOL WaitForWtsService(DWORD dwWaitMs)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteNumberInfo(M, FL, FN, L"WaitMs", dwWaitMs);

    BOOL bReturn = FALSE;

    //
    // Try to wait for the needed service(s) to be started.
    //
    HANDLE hWtsEvent = OpenEvent(SYNCHRONIZE, FALSE, L"Global\\TermSrvReadyEvent");

    if (hWtsEvent)
    {
        if (WaitForSingleObject(hWtsEvent, dwWaitMs) == WAIT_OBJECT_0)
        {
            bReturn = TRUE;
        }

        CloseHandle(hWtsEvent);
    }

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL GetCurrentProcessPath(wchar_t *pszModulePath, DWORD *pcchLen)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"ModulePath", pszModulePath);
    EventWritePointerInfo(M, FL, FN, L"LenPtr", pcchLen);
    EventWriteNumberInfo(M, FL, FN, L"Len", *pcchLen);

    HRESULT hr = S_OK;
    size_t cchLen = 0;

    if (!pcchLen) return FALSE;

    TCHAR szModulePath[MAX_PATH] = { 0 };

    if (!GetModuleFileName(NULL, szModulePath, *pcchLen))
    {
        EventWriteLastError(M, FL, FN, L"GetModuleFileName", GetLastError());
        *pcchLen = 0;
        return FALSE;
    }

    hr = PathCchRemoveFileSpec(szModulePath, *pcchLen);

    if (FAILED(hr))
    {
        EventWriteHresultError(M, FL, FN, L"PathRemoveFileSpec", hr);
        *pcchLen = 0;
        return FALSE;
    }

    StringCchCopy(pszModulePath, *pcchLen, szModulePath);

    StringCchLength(szModulePath, *pcchLen, &cchLen);

    *pcchLen = cchLen;

    EventWriteNumberInfo(M, FL, FN, L"OutLen", cchLen);

    EventWriteFunctionExit(M, FL, FN);

    return TRUE;
}

_declspec(dllexport) BOOL IsAdminUser()
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bResult;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    bResult = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup);

    if (bResult)
    {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &bResult))
        {
            bResult = FALSE;
        }

        FreeSid(AdministratorsGroup);
    }
    else
    {
        EventWriteLastError(M, FL, FN, L"AllocateAndInitializeSid", GetLastError());
    }

    EventWriteBoolInfo(M, FL, FN, L"bResult", bResult);

    EventWriteFunctionExit(M, FL, FN);

    return bResult;
}

#define SWAPWORDS(x) ((x << 16) | (x >> 16))

//
// Use the predefined version information Unicode strings from http://msdn.microsoft.com/en-us/library/windows/desktop/ms647464(v=vs.85).aspx
// for pszPreDefInfo. Or MSDN page for VerQueryValue API.
//
// If *pcbSize is lesser than the actual output, API will fail and *pcbSize will contain the required output size.
//
_declspec(dllexport) BOOL GetFileVersionInformation(wchar_t *pszFile, wchar_t *pszPreDefInfo, wchar_t *pszOutInfo, PUINT pcbSize)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"File", pszFile);
    EventWriteWideStrInfo(M, FL, FN, L"PredefInfo", pszPreDefInfo);
    EventWritePointerInfo(M, FL, FN, L"OutInfoPtr", pszOutInfo);
    EventWritePointerInfo(M, FL, FN, L"SizePtr", pcbSize);

    if (!pszFile) return FALSE;
    if (!pszPreDefInfo) return FALSE;
    if (!pszOutInfo) return FALSE;
    if (!pcbSize) return FALSE;

    BOOL bReturn = FALSE;
    BYTE *pVersionInfoBlock = NULL;
    wchar_t szSubBlock[50];
    LPVOID lpBuffer = NULL;
    UINT cbTranslate = 0;
    UINT cbSize = 0;

    DWORD dwSize = GetFileVersionInfoSize(pszFile, NULL);

    if (dwSize)
    {
        EventWriteNumberInfo(M, FL, FN, L"VersionInfoSize", dwSize);

        pVersionInfoBlock = (BYTE*)malloc(dwSize);

        if (pVersionInfoBlock)
        {
            if (GetFileVersionInfo(pszFile, 0, dwSize, pVersionInfoBlock))
            {
                LPDWORD pdwVarTrans;

                if (VerQueryValue(pVersionInfoBlock, L"\\VarFileInfo\\Translation", (LPVOID*)&pdwVarTrans, &cbTranslate))
                {
                    wchar_t szVarTrans[9];

                    StringCchPrintf(szVarTrans, 9, L"%08X", SWAPWORDS(*pdwVarTrans));
                    StringCchPrintf(szSubBlock, 50, L"\\StringFileInfo\\%s\\%s", szVarTrans, pszPreDefInfo);

                    EventWriteWideStrInfo(M, FL, FN, L"SubBlock", szSubBlock);

                    if (VerQueryValue(pVersionInfoBlock, szSubBlock, &lpBuffer, &cbSize))
                    {
                        EventWriteWideStrInfo(M, FL, FN, L"VerQueryValue", (wchar_t*)lpBuffer);
                        EventWriteNumberInfo(M, FL, FN, L"VerQueryValueSize", cbSize);

                        if (*pcbSize < cbSize)
                        {
                            EventWriteNumberError(M, FL, FN, L"Insufficient size", *pcbSize);
                            EventWriteNumberError(M, FL, FN, L"Return correct size", cbSize);

                            *pcbSize = cbSize;
                        }
                        else
                        {
                            StringCchCopy(pszOutInfo, (*pcbSize / sizeof(wchar_t)), (wchar_t*)lpBuffer);
                            *pcbSize = cbSize;
                            bReturn = TRUE;
                        }
                    }
                    else
                    {
                        EventWriteLastError(M, FL, FN, L"VerQueryValue", GetLastError());
                    }
                }
                else
                {
                    EventWriteLastError(M, FL, FN, L"VerQueryValue", GetLastError());
                }
            }
            else
            {
                EventWriteLastError(M, FL, FN, L"GetFileVersionInfo", GetLastError());
            }

            free(pVersionInfoBlock);
        }
    }

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL SetEventWithCheck(HANDLE hEvent)
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;

    if (hEvent)
    {
        bReturn = SetEvent(hEvent);
    }

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL ResetEventWithCheck(HANDLE hEvent)
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;

    if (hEvent)
    {
        bReturn = ResetEvent(hEvent);
    }

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL PulseEventWithCheck(HANDLE hEvent)
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;

    if (hEvent)
    {
        bReturn = PulseEvent(hEvent);
    }

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL IsWindows8()
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;

    if (!IsWindowsServer())
    {
        if (IsWindows8OrGreater() && !IsWindows8Point1OrGreater())
        {
            bReturn = TRUE;
        }
    }

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

_declspec(dllexport) BOOL IsWindows8OrLaterCustom()
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;
    wchar_t *pszNt = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    wchar_t szVersion[MAX_PATH];
    DWORD cbSize = sizeof(szVersion);
    double lfVersion;

    ReadSzAuto(HKEY_LOCAL_MACHINE, pszNt, L"CurrentVersion", szVersion, &cbSize);

    lfVersion = _wtof(szVersion);

    if (lfVersion >= 6.2)
    {
        bReturn = TRUE;
    }

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

//
// Temporary version checking until build environment is upgraded to 8.1. Need to use VersionHelpers.h after update.
//
_declspec(dllexport) BOOL IsWindowsBlueOrLaterCustom()
{
    EventWriteFunctionEntry(M, FL, FN);

    BOOL bReturn = FALSE;
    wchar_t *pszNt = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    wchar_t szVersion[MAX_PATH];
    DWORD cbSize = sizeof(szVersion);
    double lfVersion;

    ReadSzAuto(HKEY_LOCAL_MACHINE, pszNt, L"CurrentVersion", szVersion, &cbSize);

    lfVersion = _wtof(szVersion);

    if (lfVersion >= 6.3)
    {
        bReturn = TRUE;
    }

    EventWriteBoolInfo(M, FL, FN, L"bReturn", bReturn);

    EventWriteFunctionExit(M, FL, FN);

    return bReturn;
}

inline void DumpPackageDetails(const PACKAGE_INFO *pPackageInfo)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWritePointerInfo(M, FL, FN, L"PackageInfoPtr", pPackageInfo);

    UINT32 flags = pPackageInfo->flags;

    if ((flags & PACKAGE_FILTER_HEAD) == PACKAGE_FILTER_HEAD)
    {
        EventWriteInfoW(M, FL, FN, L"(HEAD)");
    }

    if ((flags & PACKAGE_FILTER_DIRECT) == PACKAGE_FILTER_DIRECT)
    {
        EventWriteInfoW(M, FL, FN, L"(DIRECT)");
    }

    if ((flags & PACKAGE_PROPERTY_FRAMEWORK) == PACKAGE_PROPERTY_FRAMEWORK)
    {
        EventWriteInfoW(M, FL, FN, L"(FRAMEWORK)");
    }

    EventWriteWideStrInfo(M, FL, FN, L"Path", pPackageInfo->path);

    const PACKAGE_ID *pPackageId = &(pPackageInfo->packageId);

    EventWriteWideStrInfo(M, FL, FN, L"Name", pPackageId->name);
    EventWriteWideStrInfo(M, FL, FN, L"Publisher", pPackageId->publisher);
    EventWriteWideStrInfo(M, FL, FN, L"PublisherID", pPackageId->publisherId);

    EventWriteNumberInfo(M, FL, FN, L"Version (Maj)", pPackageId->version.Major);
    EventWriteNumberInfo(M, FL, FN, L"Version (Min)", pPackageId->version.Minor);
    EventWriteNumberInfo(M, FL, FN, L"Version (Bld)", pPackageId->version.Build);
    EventWriteNumberInfo(M, FL, FN, L"Version (Rev)", pPackageId->version.Revision);

    EventWriteNumberInfo(M, FL, FN, L"Architecture", pPackageId->processorArchitecture);

    if (pPackageId->resourceId != NULL)
    {
        EventWriteWideStrInfo(M, FL, FN, L"Resource", pPackageId->resourceId);
    }

    EventWriteFunctionExit(M, FL, FN);
}

//
// Caller of this function should free() ppBuffer afterwards.
//
_declspec(dllexport) LONG GetWinRTApplicationInfoFromFamilyName(wchar_t *pszFamilyName, void **ppBuffer, DWORD *pcbSize, DWORD *pdwCount)
{
    EventWriteWideStrInfo(M, FL, FN, L"FamilyName", pszFamilyName);
    EventWritePointerInfo(M, FL, FN, L"OutBuffer", ppBuffer);
    EventWritePointerInfo(M, FL, FN, L"SizePtr", pcbSize);
    EventWritePointerInfo(M, FL, FN, L"CntPtr", pdwCount);

    if (!pszFamilyName) return ERROR_BAD_ARGUMENTS;
    if (!ppBuffer) return ERROR_BAD_ARGUMENTS;
    if (!pcbSize) return ERROR_BAD_ARGUMENTS;
    if (!pdwCount) return ERROR_BAD_ARGUMENTS;

    UINT32 uCnt = 0;
    UINT32 uLen = 0;

    LONG lCode = GetPackagesByPackageFamily(pszFamilyName, &uCnt, NULL, &uLen, NULL);

    if (lCode == ERROR_SUCCESS)
    {
        EventWriteInfoW(M, FL, FN, L"No package found.");
        return ERROR_NOT_FOUND;
    }
    else if (lCode != ERROR_INSUFFICIENT_BUFFER)
    {
        EventWriteLastError(M, FL, FN, L"GetPackagesByPackageFamily", lCode);
        return lCode;
    }

    PWSTR *pszFullNames = (PWSTR*)malloc(uCnt * sizeof(*pszFullNames));

    if (pszFullNames == NULL)
    {
        EventWriteErrorW(M, FL, FN, L"Memory allocation failed.");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    PWSTR pszBuffer = (PWSTR)malloc(uLen * sizeof(WCHAR));

    if (pszBuffer == NULL)
    {
        EventWriteErrorW(M, FL, FN, L"Memory allocation failed.");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    lCode = GetPackagesByPackageFamily(pszFamilyName, &uCnt, pszFullNames, &uLen, pszBuffer);

    if (lCode != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"GetPackagesByPackageFamily", lCode);
    }
    else
    {
        for (UINT32 i = 0; i < uCnt; ++i)
        {
            EventWriteWideStrInfo(M, FL, FN, L"Fullname", pszFullNames[i]);

            PVOID pBuffer = NULL;
            DWORD cbSize = 0;
            DWORD dwCnt = 0;

            GetWinRTApplicationInfoFromFullName(pszFullNames[i], &pBuffer, &cbSize, &dwCnt);

            if (pBuffer) free(pBuffer);
        }
    }

    free(pszBuffer);
    free(pszFullNames);

    return lCode;
}

//
// Caller of this function should free() ppBuffer afterwards.
//
_declspec(dllexport) LONG GetWinRTApplicationInfoFromFullName(wchar_t *pszFullName, void **ppBuffer, DWORD *pcbSize, DWORD *pdwCount)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteWideStrInfo(M, FL, FN, L"FullName", pszFullName);
    EventWritePointerInfo(M, FL, FN, L"OutBuffer", ppBuffer);
    EventWritePointerInfo(M, FL, FN, L"SizePtr", pcbSize);
    EventWritePointerInfo(M, FL, FN, L"CountPtr", pdwCount);

    if (!pszFullName) return ERROR_BAD_ARGUMENTS;
    if (!ppBuffer) return ERROR_BAD_ARGUMENTS;
    if (!pcbSize) return ERROR_BAD_ARGUMENTS;
    if (!pdwCount) return ERROR_BAD_ARGUMENTS;

    PACKAGE_INFO_REFERENCE pir = { 0 };

    LONG rc = OpenPackageInfoByFullName(pszFullName, 0, &pir);

    if (rc != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"OpenPackageInfoByFullName", rc);
        return rc;
    }

    UINT32 cnt;
    UINT32 len = 0;

    rc = GetPackageInfo(pir, PACKAGE_FILTER_HEAD | PACKAGE_FILTER_DIRECT, &len, NULL, &cnt);

    if (rc != ERROR_INSUFFICIENT_BUFFER)
    {
        EventWriteLastError(M, FL, FN, L"GetPackageInfo", rc);
        ClosePackageInfo(pir);
        return rc;
    }

    *ppBuffer = (BYTE*)malloc(len);

    if (*ppBuffer == NULL)
    {
        EventWriteErrorW(M, FL, FN, L"Memory allocation failed.");
        ClosePackageInfo(pir);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    rc = GetPackageInfo(pir, PACKAGE_FILTER_HEAD | PACKAGE_FILTER_DIRECT, &len, (BYTE*)*ppBuffer, &cnt);

    if (rc != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"GetPackageInfo", rc);
        ClosePackageInfo(pir);
        return rc;
    }

    const PACKAGE_INFO *pInfo = (PACKAGE_INFO*)*ppBuffer;

    for (UINT32 i = 0; i < cnt; ++i, ++pInfo)
    {
        EventWriteNumberInfo(M, FL, FN, L"Package Index", i);
        DumpPackageDetails(pInfo);
    }

    rc = ClosePackageInfo(pir);

    if (rc != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"ClosePackageInfo", rc);
        return rc;
    }

    EventWriteFunctionExit(M, FL, FN);

    return rc;
}

_declspec(dllexport) LONG GetWinRTApplicationFullName(const UINT32 pid, HANDLE hProcess, wchar_t *pszOutStr, DWORD *pcchOutLen)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteNumberInfo(M, FL, FN, L"PID", pid);
    EventWriteHexInfo(M, FL, FN, L"ProcessHandle", (UINT)hProcess);
    EventWritePointerInfo(M, FL, FN, L"OutPtr", pszOutStr);
    EventWritePointerInfo(M, FL, FN, L"LenPtr", pcchOutLen);

    if (!pszOutStr) return ERROR_BAD_ARGUMENTS;
    if (!pcchOutLen) return ERROR_BAD_ARGUMENTS;

    UINT32 len = 0;

    LONG rc = GetPackageFullName(hProcess, &len, NULL);

    if (rc != ERROR_INSUFFICIENT_BUFFER)
    {
        if (rc == APPMODEL_ERROR_NO_PACKAGE)
        {
            EventWriteErrorW(M, FL, FN, L"APPMODEL_ERROR_NO_PACKAGE: No package identity.");
        }
        else
        {
            EventWriteLastError(M, FL, FN, L"GetPackageFullName", rc);
        }

        return rc;
    }

    PWSTR pszFullName = (PWSTR)malloc(len * sizeof(*pszFullName));

    if (pszFullName == NULL)
    {
        EventWriteErrorW(M, FL, FN, L"Memory allocation failed.");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    rc = GetPackageFullName(hProcess, &len, pszFullName);

    if (rc != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"GetPackageFullName", rc);
    }
    else
    {
        EventWriteWideStrInfo(M, FL, FN, L"FullName", pszFullName);

        if (*pcchOutLen < len)
        {
            rc = ERROR_INSUFFICIENT_BUFFER;
        }
        else
        {
            StringCchCopy(pszOutStr, (size_t)(*pcchOutLen), pszFullName);
            *pcchOutLen = (DWORD)len;
            rc = ERROR_SUCCESS;
        }
    }

    free(pszFullName);

    EventWriteFunctionExit(M, FL, FN);

    return rc;
}

_declspec(dllexport) LONG GetWinRTApplicationFamilyName(const UINT32 pid, HANDLE hProcess, wchar_t *pszOutStr, DWORD *pcchOutLen)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteNumberInfo(M, FL, FN, L"PID", pid);
    EventWriteHexInfo(M, FL, FN, L"ProcessHandle", (UINT)hProcess);
    EventWritePointerInfo(M, FL, FN, L"OutPtr", pszOutStr);
    EventWritePointerInfo(M, FL, FN, L"LenPtr", pcchOutLen);

    if (!pszOutStr) return ERROR_BAD_ARGUMENTS;
    if (!pcchOutLen) return ERROR_BAD_ARGUMENTS;

    UINT32 len = 0;

    LONG rc = GetPackageFamilyName(hProcess, &len, NULL);

    if (rc != ERROR_INSUFFICIENT_BUFFER)
    {
        if (rc == APPMODEL_ERROR_NO_PACKAGE)
        {
            EventWriteErrorW(M, FL, FN, L"APPMODEL_ERROR_NO_PACKAGE: No package identity.");
        }
        else
        {
            EventWriteLastError(M, FL, FN, L"GetPackageFamilyName", rc);
        }

        return rc;
    }

    PWSTR pszFamilyName = (PWSTR)malloc(len * sizeof(*pszFamilyName));

    if (pszFamilyName == NULL)
    {
        EventWriteErrorW(M, FL, FN, L"Memory allocation failed.");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    rc = GetPackageFamilyName(hProcess, &len, pszFamilyName);

    if (rc != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"GetPackageFamilyName", rc);
    }
    else
    {
        EventWriteWideStrInfo(M, FL, FN, L"FamilyName", pszFamilyName);

        if (*pcchOutLen < len)
        {
            rc = ERROR_INSUFFICIENT_BUFFER;
        }
        else
        {
            StringCchCopy(pszOutStr, (size_t)(*pcchOutLen), pszFamilyName);
            *pcchOutLen = (DWORD)len;
            rc = ERROR_SUCCESS;
        }
    }

    free(pszFamilyName);

    EventWriteFunctionExit(M, FL, FN);

    return rc;
}

_declspec(dllexport) LONG GetWinRTApplicationUserModelId(const UINT32 pid, HANDLE hProcess, wchar_t *pszOutStr, DWORD *pcchOutLen)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWriteNumberInfo(M, FL, FN, L"PID", pid);
    EventWriteHexInfo(M, FL, FN, L"ProcessHandle", (UINT)hProcess);
    EventWritePointerInfo(M, FL, FN, L"OutPtr", pszOutStr);
    EventWritePointerInfo(M, FL, FN, L"LenPtr", pcchOutLen);

    if (!pszOutStr) return ERROR_BAD_ARGUMENTS;
    if (!pcchOutLen) return ERROR_BAD_ARGUMENTS;

    UINT32 len = 0;

    LONG rc = GetApplicationUserModelId(hProcess, &len, NULL);

    if (rc != ERROR_INSUFFICIENT_BUFFER)
    {
        if (rc == APPMODEL_ERROR_NO_APPLICATION)
        {
            EventWriteInfoW(M, FL, FN, L"Desktop application!");
        }
        else
        {
            EventWriteLastError(M, FL, FN, L"GetApplicationUserModelId", rc);
        }

        return rc;
    }

    PWSTR pszUserModelId = (PWSTR)malloc(len * sizeof(*pszUserModelId));

    if (pszUserModelId == NULL)
    {
        EventWriteErrorW(M, FL, FN, L"Memory allocation failed.");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    rc = GetApplicationUserModelId(hProcess, &len, pszUserModelId);

    if (rc != ERROR_SUCCESS)
    {
        EventWriteLastError(M, FL, FN, L"GetApplicationUserModelId", rc);
    }
    else
    {
        EventWriteWideStrInfo(M, FL, FN, L"UserModelId", pszUserModelId);

        if (*pcchOutLen < len)
        {
            rc = ERROR_INSUFFICIENT_BUFFER;
        }
        else
        {
            StringCchCopy(pszOutStr, (size_t)(*pcchOutLen), pszUserModelId);
            *pcchOutLen = (DWORD)len;
            rc = ERROR_SUCCESS;
        }
    }

    free(pszUserModelId);

    EventWriteFunctionExit(M, FL, FN);

    return rc;
}

HRESULT GetAllTextElements(IUIAutomation** ppAuto, IUIAutomationElement** ppParent, IUIAutomationElementArray** ppOut)
{
    CComPtr<IUIAutomationCondition> pCondition = NULL;
    VARIANT varProp;
    varProp.vt = VT_I4;
    varProp.lVal = UIA_EditControlTypeId;

    (*ppAuto)->CreatePropertyCondition(UIA_ControlTypePropertyId, varProp, &pCondition);
    if (!pCondition) return E_FAIL;

    HRESULT hr = (*ppParent)->FindAll(TreeScope_Subtree, pCondition, &(*ppOut));
    if (FAILED(hr) || !(*ppOut)) return E_FAIL;

    return S_OK;
}

HRESULT GetMainParentElement(IUIAutomation** ppAuto, IUIAutomationElement** ppChild, IUIAutomationElement** ppParent)
{
    IUIAutomationElement* pNode = NULL;
    CComPtr<IUIAutomationTreeWalker> pWalker = NULL;
    CComPtr<IUIAutomationElement> pDesktop = NULL;
    CComPtr<IUIAutomationElement> pParentTemp = NULL;

    pNode = *ppChild;

    HRESULT hr = (*ppAuto)->GetRootElement(&pDesktop);
    if (FAILED(hr)) return hr;

    BOOL bSame;

    (*ppAuto)->CompareElements(pDesktop, pNode, &bSame);
    if (bSame) return E_FAIL;

    (*ppAuto)->get_ControlViewWalker(&pWalker);
    if (!pWalker) return E_FAIL;

    while (TRUE)
    {
        hr = pWalker->GetParentElement(pNode, &pParentTemp);
        if (FAILED(hr) || !pParentTemp) break;

        (*ppAuto)->CompareElements(pParentTemp, pDesktop, &bSame);

        if (bSame)
        {
            *ppParent = pNode;
            return S_OK;
        }

        if (pNode != *ppChild) pNode->Release();
        pNode = pParentTemp;
    }

    if ((pNode != NULL) && (pNode != *ppChild)) pNode->Release();

    return E_FAIL;
}

//
// Need to call CoInitialize(...) before calling this function.
//
_declspec(dllexport) HRESULT GetProcessIdFromFocusedElement(DWORD *pdwProcessId)
{
    EventWriteFunctionEntry(M, FL, FN);

    EventWritePointerInfo(M, FL, FN, L"PidPtr", pdwProcessId);

    CComPtr<IUIAutomation> spAuto;
    CComPtr<IUIAutomationElement> spItem;

    HRESULT hr = CoCreateInstance(__uuidof(CUIAutomation), NULL, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&spAuto);

    if (SUCCEEDED(hr) && spAuto)
    {
        hr = spAuto->GetFocusedElement(&spItem);

        if (SUCCEEDED(hr) && spItem)
        {
            int procid = 0;
            spItem->get_CurrentProcessId(&procid);

            EventWriteNumberInfo(M, FL, FN, L"Focused Process ID", procid);

            if (pdwProcessId) *pdwProcessId = (DWORD)procid;
        }
        else
        {
            EventWriteHresultError(M, FL, FN, L"GetFocusedElement", hr);

            DWORD cchLen = MAX_PATH;
            wchar_t szTrace[MAX_PATH];

            GetComTextError(hr, szTrace, &cchLen);
            EventWriteHexError(M, FL, FN, szTrace, hr);
        }
    }

    EventWriteFunctionExit(M, FL, FN);

    return hr;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CSomeClass : public ISomeClass {
public:
    CSomeClass() :
        m_lRefCount(0)
    {}

    virtual ~CSomeClass() {}

    //
    // IUnknown methods.
    //
    STDMETHODIMP QueryInterface(REFIID iid, void **ppv)
    {
        if ((iid == __uuidof(IUnknown)) || (iid == __uuidof(ISomeClass)))
        {
            *ppv = static_cast<CSomeClass*>(this);
        }
        else
        {
            *ppv = NULL;
            return E_NOINTERFACE;
        }

        AddRef();
        return S_OK;
    }

    STDMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&m_lRefCount);
    }

    STDMETHODIMP_(ULONG) Release()
    {
        ULONG uCount = InterlockedDecrement(&m_lRefCount);

        if (uCount == 0)
        {
            delete this;
        }

        return uCount;
    }

    //
    // ISomeClass methods.
    //
    LONG Add(LONG a, LONG b)
    {
        return a + b;
    }

    LONG Subtract(LONG a, LONG b)
    {
        return a - b;
    }

private:
    LONG m_lRefCount;
    HINSTANCE m_hDllInst;
};

_declspec(dllexport) HRESULT CreateSomeClassInstance(ISomeClass **ppObj)
{
    if (ppObj == NULL) return E_POINTER;

    ISomeClass *pObj = new (std::nothrow) CSomeClass();

    if (pObj == NULL) return E_OUTOFMEMORY;

    *ppObj = pObj;

    (*ppObj)->AddRef();

    return S_OK;
}


