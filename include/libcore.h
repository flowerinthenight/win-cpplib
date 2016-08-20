/*
* Copyright(c) 2016 Chew Esmero
* All rights reserved.
*/

#pragma once

#include <Windows.h>
#include <Unknwn.h>
#include <objbase.h>
#include <shobjidl.h>
#include <winioctl.h>
#include <UIAutomation.h>
#include "sdkdefines.h"
#ifndef _MANAGED
#include <wrl\client.h>
#include <wrl\implements.h>
#endif _MANAGED

struct __declspec(uuid("AE557F48-A2D9-4819-8CDC-99A88DF696AE")) ISomeClass;
struct __declspec(uuid("3F9887C0-F321-42E7-9743-C6888249CC8F")) ICommon4;
struct __declspec(uuid("88E0CA48-0DE9-4723-95B9-80A96AE2B766")) IAccessibility1;
struct __declspec(uuid("6CF243D4-34CC-434B-9C63-A0447460269D")) IAppVisibilityWithCallback;
struct __declspec(uuid("464C0A7E-801F-4009-B762-E3791F6EAF52")) IATLServiceWinProcSupport;
struct __declspec(uuid("9B00F076-CADC-4B1D-8F34-663C7D633352")) IProcessUtil;
struct __declspec(uuid("2D4841AE-EF1C-48FA-9ABF-17528A69B2D9")) IImpersonation;
struct __declspec(uuid("B5266B77-ADDD-4A3F-ADD1-9E56D45F1631")) IRunThread;
struct __declspec(uuid("5D09DEC6-82D4-48F8-B693-FC11148270D5")) IThreadPool;
struct __declspec(uuid("EB90E14C-6762-4BB4-9AAC-D4CA98C234F2")) INoOverlapTimer;
struct __declspec(uuid("24E3FF34-6565-44B4-BA1B-91D5C7D5CA38")) IDllCallProxy;
struct __declspec(uuid("AE183B43-D527-4A6F-8E25-7BF2E354606A")) IPmDriverAccess;
struct __declspec(uuid("9948057C-115E-48F9-BDBB-B722F6FA8182")) IWindowCustomWinProc;

#define MAX_WAIT_EVENTS 3

typedef enum {
    REG_REDIRECT_32,
    REG_REDIRECT_64,
    REG_REDIRECT_AUTO,
    REG_REDIRECT_TOTAL,
};

typedef enum RestartTypeEnum {
    RESTART_INTERACTIVE,
    RESTART_NONINTERACTIVE,
    RESTART_TIMED,
    RESTART_CANCEL,
    RESTART_TOTAL
};

typedef enum CamListLocEnum {
    CAMLIST_FRONT,
    CAMLIST_REAR
};

typedef enum {
    WINSTA0_DEFAULT,
    WINSTA0_WINLOGON,
} WINSTA0_DESKTOP;

enum EnumEventCategory {
    EVENT_CATEGORY_SESSION_0,
    EVENT_CATEGORY_SESSION_USER,
};

enum EnumEventType {
    EVENT_TYPE_INFORMATION,
    EVENT_TYPE_WARNING,
    EVENT_TYPE_ERROR,
};

typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
typedef int(*FnDispatchParam)(wchar_t *pszParam, wchar_t *pszSubParam, PVOID pContext);
typedef int(*FnRundllDispatch)();

typedef struct __ARG_DISPATCH_TABLE {
    wchar_t szParam[MAX_PATH];
    FnDispatchParam pfnDispatch;
} ARG_DISPATCH_TABLE, *PARG_DISPATCH_TABLE;

typedef void (CALLBACK *FnWinEventProc)(
    HWINEVENTHOOK hWinEventHook,
    DWORD dwEvent,
    HWND hWnd,
    LONG idObject,
    LONG idChild,
    DWORD dwEventThread,
    DWORD dwEventTimeMs);

typedef HRESULT(WINAPI *FnAppVisibilityOnMonitorChanged)(
    HMONITOR hMonitor,
    MONITOR_APP_VISIBILITY previousAppVisibility,
    MONITOR_APP_VISIBILITY currentAppVisibility);

typedef HRESULT(WINAPI *FnLauncherVisibilityChanged)(BOOL bCurrentVisibleState);

typedef BOOL(NTAPI *PTP_TIMER_CALLBACK_CUSTOM)(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer);

typedef struct __DispatchParam {
    HANDLE hTerminate;
} DispatchParam, *PDispatchParam;

typedef struct __ApcContext {
    DWORD dwControl;
    LONG lParam1;
    wchar_t szParam1[MAX_PATH];
} ApcContext, *PApcContext;

class WaitMultipleEvent {
public:
    WaitMultipleEvent()
    {
        hEvent = NULL;
        bIsManual = FALSE;
        pfnDispatch = NULL;
        bInternal = FALSE;
    }

    virtual ~WaitMultipleEvent()
    {
        if (bInternal && hEvent) CloseHandle(hEvent);
    }

    HANDLE hEvent;
    BOOL bIsManual;
    FnGenericFunction pfnDispatch;
    BOOL bInternal;
};

class WaitMultipleContext {
public:
    WaitMultipleContext()
    {
        dwSleep = 0;
        bWaitAll = FALSE;
        dwTermIndex = 0;
        dwWaitTime = INFINITE;
    }

    DWORD dwSleep;
    DWORD dwWaitTime;
    BOOL bWaitAll;
    DWORD dwTermIndex;
    WaitMultipleEvent pEvents[MAX_WAIT_EVENTS];
};

typedef struct __UserImpersonationContext {
    DWORD dwSleep;
    BOOL bWaitExit;
    BOOL bReturn;
    DWORD dwWaitMs;
    DWORD dwExitCode;
    wchar_t szApp[MAX_PATH];
} UserImpersonationContext, *PUserImpersonationContext;

typedef struct __TPTIMER_CONTEXT {
    BOOL bSet;
    PTP_TIMER pTimer;
} TPTIMER_CONTEXT, *PTPTIMER_CONTEXT;

union FILETIME64
{
    INT64 quad;
    FILETIME ft;
};

//
// Simple COM-like wrapper interfaces.
//
struct ISomeClass : public IUnknown {
    virtual LONG Add(LONG a, LONG b) = 0;
    virtual LONG Subtract(LONG a, LONG b) = 0;
};

struct ICommon4 : public IUnknown {
    virtual HRESULT RestartSystemInteractive(RestartTypeEnum rt) = 0;
    virtual HRESULT DotNetInstalled(DotNetVersions dnv, PBOOL pbInstalled) = 0;
    virtual BOOL IsFriendlyNameSupported(wchar_t *pszFName) = 0;
};

struct IAccessibility1 : public IUnknown {
    virtual HWINEVENTHOOK SubscribeWinEvent(DWORD dwMinEvent, DWORD dwMaxEvent, FnWinEventProc pfnWinEventProc) = 0;
    virtual BOOL UnsubscribeWinEvent() = 0;
};

struct IATLServiceWinProcSupport : public IUnknown {
    virtual BOOL Initialize(WNDPROC pfnWindowProc) = 0;
    virtual void Close() = 0;
};

//
// Since the visibility notifications are delivered via COM, a message loop must be employed by the caller
// in order to receive notifications.
//
struct IAppVisibilityWithCallback : public IUnknown {
    virtual HRESULT Subscribe(
        FnAppVisibilityOnMonitorChanged pfnVisibilityOnMonitorCb,
        FnLauncherVisibilityChanged pfnLauncherVisibilityCb) = 0;
    virtual HRESULT Unsubscribe() = 0;
};

struct IProcessUtil : public IUnknown {
    virtual BOOL StartSystemUserProcess(wchar_t *pszCmd, wchar_t *pszParam) = 0;
    virtual BOOL IsServiceActive(wchar_t *pszName) = 0;
    virtual BOOL IsProcessInRunState(wchar_t *pszProcessName, DWORD *pdwProcessId) = 0;
    virtual BOOL HiddenExecute(wchar_t *pszFile, wchar_t *pszDir, wchar_t *pszParams, DWORD *pdwExitCode, BOOL bWaitTerm, DWORD dwWaitMs) = 0;
    virtual BOOL IsDllLoaded(wchar_t *pszDllName, PDWORD pdwProcessId) = 0;
};

//
// This requires SYSTEM privileges in order to function properly.
//
struct IImpersonation : public IUnknown {
    virtual DWORD ImpersonateExecute(UserImpersonationContext *pParam) = 0;
};

struct IRunThread : public IUnknown {
    virtual BOOL RegisterThreadForTerminationWaitAtomic(DWORD dwThreadId) = 0;
    virtual DWORD GetThreadIndexAtomic(DWORD dwThrId) = 0;
    virtual DWORD GetTotalThreadsAtomic() = 0;
    virtual PHANDLE GetEventsHandle() = 0;
};

struct IThreadPool : public IUnknown {
    virtual PTP_POOL GetThreadPoolObject() = 0;
    virtual PTP_CLEANUP_GROUP GetCleanupGroupObject() = 0;
    virtual PTP_CALLBACK_ENVIRON GetCallbackEnvironmentObject() = 0;
    virtual BOOL Initialize(LONG lMinThreads, LONG lMaxThreads, PTP_CLEANUP_GROUP_CANCEL_CALLBACK pfnGrpCancelCb) = 0;
    virtual void Close(BOOL bCancel, PVOID pContext) = 0;
    virtual void SetupWorkCallback(PTP_WORK_CALLBACK pfnWorkCallback, PVOID pContext) = 0;
    virtual void SetupWaitCallback(PTP_WAIT_CALLBACK pfnWaitCallback, PVOID pContext, HANDLE hEvent) = 0;
    virtual LONG SetupTimerCallback(PTP_TIMER_CALLBACK pfnTimerCallback, PVOID pContext, LONG lDueTimeMs, LONG lPeriodMs, LONG lDelay) = 0;
    virtual void CloseTimer(LONG lIndex) = 0;
};

struct INoOverlapTimer : public IUnknown {
    virtual HRESULT StartTimer(DWORD dwInitialTimeMs, PTP_TIMER_CALLBACK_CUSTOM pfnTimerCallback) = 0;
};

struct IDllCallProxy : public IUnknown {
    virtual FARPROC GetProcAddr(LPCSTR pszProcName) = 0;
};

struct IWindowCustomWinProc : public IUnknown {
    virtual BOOL Initialize(WNDPROC pfnWindowProc) = 0;
    virtual void Close() = 0;
};

#ifdef __cplusplus
extern "C" {
#endif

    //
    // Registry functions.
    //
    _declspec(dllexport) LSTATUS ReadBin32(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, BYTE *pData, DWORD *pcbData);
    _declspec(dllexport) LSTATUS ReadBin64(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, BYTE *pData, DWORD *pcbData);
    _declspec(dllexport) LSTATUS ReadBinAuto(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, BYTE *pData, DWORD *pcbData);
    _declspec(dllexport) LSTATUS WriteBin32(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, BYTE *pData, DWORD cbData);
    _declspec(dllexport) LSTATUS WriteBin64(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, BYTE *pData, DWORD cbData);
    _declspec(dllexport) LSTATUS WriteBinAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, BYTE *pData, DWORD cbData);
    _declspec(dllexport) LSTATUS ReadDword32(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, DWORD *pdwData);
    _declspec(dllexport) LSTATUS ReadDword64(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, DWORD *pdwData);
    _declspec(dllexport) LSTATUS ReadDwordAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD *pdwData);
    _declspec(dllexport) LSTATUS WriteDword32(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD dwData);
    _declspec(dllexport) LSTATUS WriteDword64(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD dwData);
    _declspec(dllexport) LSTATUS WriteDwordAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD dwData);
    _declspec(dllexport) LSTATUS ReadSz32(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize);
    _declspec(dllexport) LSTATUS ReadSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize);
    _declspec(dllexport) LSTATUS WriteSz32(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, wchar_t *pszData);
    _declspec(dllexport) LSTATUS WriteSz64(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, wchar_t *pszData);
    _declspec(dllexport) LSTATUS WriteSzAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, wchar_t *pszData);
    _declspec(dllexport) LSTATUS ReadMultiSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize);
    _declspec(dllexport) LSTATUS WriteMultiSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, DWORD cbSize);
    _declspec(dllexport) LSTATUS ReadExpandSz32(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize);
    _declspec(dllexport) LSTATUS ReadExpandSz64(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize);
    _declspec(dllexport) LSTATUS ReadExpandSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize);

    //
    // Core functions.
    //
    _declspec(dllexport) BOOL IsWow64();
    _declspec(dllexport) void HandleCleanup(HANDLE *pHandle);
    _declspec(dllexport) BOOL WaitForWtsService(DWORD dwWaitMs);
    _declspec(dllexport) void CreateGlobalEvent(HANDLE *pHandle, wchar_t *pszName, BOOL bManualReset = FALSE);
    _declspec(dllexport) void CreateGlobalMutex(HANDLE *pHandle, wchar_t *pszName);
    _declspec(dllexport) void SetDoubleWordAtomic(LPCRITICAL_SECTION pcs, LPDWORD pDest, DWORD dwValue);
    _declspec(dllexport) void PrintComError(HRESULT hr, wchar_t *pszMsg);
    _declspec(dllexport) HRESULT GetComTextError(HRESULT hr, wchar_t *pszOut, DWORD *pcchLen);
    _declspec(dllexport) void DumpLastError(wchar_t *pszExtra);
    _declspec(dllexport) void GetLastErrorDescription(DWORD dwLastError, wchar_t *pszOut, DWORD cchLen);
    _declspec(dllexport) void HandleCleanup(HANDLE *pHandle);
    _declspec(dllexport) BOOL EnableTokenPrivilege(LPTSTR szPrivilege);
    _declspec(dllexport) BOOL IsServiceActive(wchar_t *pszName);
    _declspec(dllexport) BOOL IsProcessInRunState(wchar_t *pszProcessName, DWORD *pdwProcessId);
    _declspec(dllexport) BOOL SendCtrlCodeToService(wchar_t *pszSvcName, DWORD dwCtrl);

    //
    // Exec family of functions.
    //
    _declspec(dllexport) BOOL StartSystemUserProcess(
        wchar_t *pszCmd,
        wchar_t *pszParam,
        WINSTA0_DESKTOP winstaDesktop,
        DWORD *pdwExitCode,
        BOOL bWaitTerm,
        DWORD dwWaitMs);

    _declspec(dllexport) BOOL NormalExecute(
        wchar_t *pszFile,
        wchar_t *pszDirectory,
        wchar_t *pszParams,
        DWORD *pdwExitCode,
        BOOL bWaitTerm,
        DWORD dwWaitMs);

    _declspec(dllexport) BOOL NormalExecuteSubsys(
        wchar_t *pszFile,
        wchar_t *pszParams,
        DWORD *pdwExitCode,
        BOOL bWaitTerm,
        DWORD dwWaitMs);

    _declspec(dllexport) BOOL HiddenExecute(
        wchar_t *pszFile,
        wchar_t *pszDirectory,
        wchar_t *pszParams,
        DWORD *pdwExitCode,
        BOOL bWaitTerm,
        DWORD dwWaitMs);

    _declspec(dllexport) BOOL HiddenExecuteSubsys(
        wchar_t *pszFile,
        wchar_t *pszParams,
        DWORD *pdwExitCode,
        BOOL bWaitTerm,
        DWORD dwWaitMs);

    _declspec(dllexport) BOOL ProxyRunDll32(
        wchar_t *pszDll,
        wchar_t *pszEntry,
        wchar_t *pszParams,
        DWORD *pdwExitCode,
        BOOL bWaitTerm,
        DWORD dwWaitMs);

    _declspec(dllexport) BOOL IsDllLoaded(wchar_t *pszDllName, PDWORD pdwProcessId);
    _declspec(dllexport) LSTATUS IsDllLoaded2(wchar_t *pszDllName, PDWORD pdwPidList, PDWORD pcbCount);
    _declspec(dllexport) BOOL SystemIsConnectedStandbyCapable();
    _declspec(dllexport) BOOL IsWindows8();
    _declspec(dllexport) BOOL IsWindows8OrLaterCustom();
    _declspec(dllexport) BOOL IsWindowsBlueOrLaterCustom();
    _declspec(dllexport) BOOL IsSupportedCameraEx(CamListLocEnum cll, wchar_t *pszFriendlyName);
    _declspec(dllexport) BOOL GetSupportedCameraName(CamListLocEnum cll, DWORD dwIndex, wchar_t *pszFriendlyName, DWORD cchDest);
    _declspec(dllexport) void DwordToBitStr(DWORD dwValue, DWORD cchLen, wchar_t *pszBits);
    _declspec(dllexport) BOOL WaitForWtsService(DWORD dwWaitMs);
    _declspec(dllexport) BOOL GetCurrentProcessPath(wchar_t *pszModulePath, DWORD *pcchLen);
    _declspec(dllexport) BOOL IsAdminUser();
    _declspec(dllexport) BOOL GetFileVersionInformation(wchar_t *pszFile, wchar_t *pszPreDefInfo, wchar_t *pszOutInfo, PUINT pcbOutLen);
    _declspec(dllexport) BOOL SetEventWithCheck(HANDLE hEvent);
    _declspec(dllexport) BOOL ResetEventWithCheck(HANDLE hEvent);
    _declspec(dllexport) BOOL PulseEventWithCheck(HANDLE hEvent);

    //
    // WinApps functions.
    //
    _declspec(dllexport) LONG GetWinRTApplicationInfoFromFamilyName(wchar_t *pszFamilyName, void **ppBuffer, DWORD *pcbSize, DWORD *pdwCount);
    _declspec(dllexport) LONG GetWinRTApplicationInfoFromFullName(wchar_t *pszFullName, void **ppBuffer, DWORD *pcbSize, DWORD *pdwCount);
    _declspec(dllexport) LONG GetWinRTApplicationFullName(const UINT32 pid, HANDLE hProcess, wchar_t *pszOutStr, DWORD *pcchOutLen);
    _declspec(dllexport) LONG GetWinRTApplicationFamilyName(const UINT32 pid, HANDLE hProcess, wchar_t *pszOutStr, DWORD *pcchOutLen);
    _declspec(dllexport) LONG GetWinRTApplicationUserModelId(const UINT32 pid, HANDLE hProcess, wchar_t *pszOutStr, DWORD *pcchOutLen);
    _declspec(dllexport) HRESULT GetProcessIdFromFocusedElement(DWORD *pdwProcessId);

    //
    // Common4 functions (deprecated).
    //
    _declspec(dllexport) HRESULT CreateCommon4Instance(ICommon4 **ppObj);

    //
    // Accessibility functions.
    //
    _declspec(dllexport) HRESULT CreateAccessibility1Instance(IAccessibility1 **ppObj);

    //
    // APC functions.
    //
    _declspec(dllexport) DWORD __stdcall InternalApcDispatcher(LPVOID lpData);
    _declspec(dllexport) DWORD RunFunctionAsync(HANDLE hThread, PAPCFUNC pFunction, ULONG_PTR pData);

    //
    // App visibility functions.
    //
    _declspec(dllexport) HRESULT CreateAppVisibilityWithCbInstance(IAppVisibilityWithCallback **ppObj);

    //
    // ATL services support functions.
    //
    _declspec(dllexport) HRESULT CreateATLServiceWinProcSupportInstance(IATLServiceWinProcSupport **ppObj);

    //
    // Event control functions.
    //
    _declspec(dllexport) DWORD __stdcall WaitMultipleCtrl(LPVOID lpData);

    //
    // Event log functions.
    //
    _declspec(dllexport) void InternalReportEvent(EnumEventType evType, EnumEventCategory evCat, LPTSTR szMessage);

    //
    // Pipe functions.
    //
    _declspec(dllexport) BOOL CreateGlobalNamedPipe(
        HANDLE *pPipeHandle,
        wchar_t *pszName,
        DWORD dwOpenMode,
        DWORD dwPipeMode,
        DWORD dwMaxInstances,
        DWORD dwOutputSize,
        DWORD dwInputSize,
        DWORD dwTimeout);

    _declspec(dllexport) BOOL NamedPipeWriteReadSync(
        wchar_t *pszName,
        LPVOID lpInputData,
        DWORD dwInputSize,
        LPVOID lpOutputData,
        DWORD dwOutputSize,
        DWORD dwOpenWaitTimeout,
        DWORD *pcbBytesWritten,
        DWORD *pcbBytesRead);

    _declspec(dllexport) BOOL ConnectToClient(HANDLE hPipe, LPOVERLAPPED lpo);
    _declspec(dllexport) void DisconnectAndReconnect(HANDLE hPipe, LPOVERLAPPED lpOverlap, BOOL *pbPendingIo, DWORD *pdwState);
    _declspec(dllexport) BOOL TerminatePipeServer(wchar_t *pszPipeName);
    _declspec(dllexport) DWORD CALLBACK DispatchPipeServerComm(LPVOID lpData);
    _declspec(dllexport) void CALLBACK DispatchPipeServerCommWork(PTP_CALLBACK_INSTANCE pInst, PVOID pContext, PTP_WORK pWork);

    //
    // Process functions.
    //
    _declspec(dllexport) HRESULT CreateProcessUtilInstance(IProcessUtil **ppObj);
    _declspec(dllexport) HRESULT CreateImpersonationInstance(IImpersonation **ppObj);

    //
    // Shared memory functions.
    //
    _declspec(dllexport) HRESULT CreateSharedMemory(HANDLE *hSharedFile, wchar_t *pszName, DWORD dwSize, LPVOID *lpBuf);
    _declspec(dllexport) HRESULT CloseSharedMemory(HANDLE *hSharedFile, LPVOID *lpBuf);
    _declspec(dllexport) HRESULT OpenSharedMemory(HANDLE *hSharedFile, wchar_t *pszName, LPVOID *lpBuf);

    //
    // Thread functions.
    //
    _declspec(dllexport) HRESULT CreateRunThreadInstance(IRunThread **ppObj);

    //
    // Threadpool functions.
    //
    _declspec(dllexport) PTP_POOL SetupThreadPool(DWORD dwMinThreads, DWORD dwMaxThreads);
    _declspec(dllexport) PTP_CLEANUP_GROUP SetupThreadPoolCleanupGroup(PTP_CALLBACK_ENVIRON pCbEnv, PTP_CLEANUP_GROUP_CANCEL_CALLBACK pfnGrpCancelCb);
    _declspec(dllexport) void ReleaseThreadPoolCleanupGroup(PTP_CLEANUP_GROUP pCleanupGroup, BOOL bCancel, PVOID pContext);
    _declspec(dllexport) HRESULT CreateThreadPoolInstance(IThreadPool **ppObj);

    //
    // Time functions.
    //
    _declspec(dllexport) FILETIME RelativeTime(DWORD dwMilliSecs);
    _declspec(dllexport) FILETIME ConvertRelativeMilliSecsToFileTime(DWORD dwMilliSecs);
    _declspec(dllexport) DWORD ConvertFiletimeToRelativeMilliSecs(FILETIME ft);
    _declspec(dllexport) time_t ConvertFiletimeToTimet(FILETIME ft);
    _declspec(dllexport) void ConvertTimetToFiletime(time_t t, FILETIME *pft);
    _declspec(dllexport) LRESULT GetWindowsLastShutdownTime(FILETIME *pft);

    //
    // Timer functions.
    //
    _declspec(dllexport) HRESULT CreateNoOverlapTimerInstance(INoOverlapTimer **ppObj);

    //
    // DLL proxy functions.
    //
    _declspec(dllexport) HRESULT CreateDllCallProxyInstance(wchar_t *pszDllName, IDllCallProxy **ppObj);

    //
    // PMDriver communication functions.
    //
    _declspec(dllexport) HRESULT CreatePmDriverAccessInstance(IPmDriverAccess **ppObj);

    //
    // Window in another thread with window procedure as parameter.
    //
    _declspec(dllexport) HRESULT CreateWindowCustomWinProcInstance(IWindowCustomWinProc **ppObj);

    //
    // UI Automation helper functions.
    //
    HRESULT GetAllTextElements(IUIAutomation** ppAuto, IUIAutomationElement** ppParent, IUIAutomationElementArray** ppOut);
    HRESULT GetMainParentElement(IUIAutomation** ppAuto, IUIAutomationElement** ppChild, IUIAutomationElement** ppParent);

    //
    // TEST
    //
    _declspec(dllexport) HRESULT CreateSomeClassInstance(ISomeClass **ppObj);

#ifdef __cplusplus
}
#endif

#ifndef SAFE_RELEASE_TEMPLATE
#define SAFE_RELEASE_TEMPLATE TRUE
template <class T> void SafeRelease(T **ppT)
{
    if (*ppT)
    {
        (*ppT)->Release();
        *ppT = NULL;
    }
}
#endif // SAFE_RELEASE_TEMPLATE

#define SAFE_RELEASE(ptr) \
{ \
	if (ptr) \
	{ \
		(ptr)->Release(); \
		(ptr) = NULL; \
	} \
}
