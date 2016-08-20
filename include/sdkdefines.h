/*
* Copyright(c) 2016 Chew Esmero
* All rights reserved.
*/

#pragma once

#include <Windows.h>

typedef HRESULT(*FnGenericFunction)(LPVOID lpParam);

#define WIDEN2(x)					L##x
#define WIDEN(x)					WIDEN2(x)
#define __WFILE__					WIDEN(__FILE__)
#define __WFUNC__					WIDEN(__FUNCTION__)
#define WFN							__FUNCTIONW__

#define SINGLE_DO_WHILE_START		do
#define SINGLE_DO_WHILE_END			while (FALSE)
#define SINGLE_DO_WHILE_BREAK		break
#define SINGLE_DO_BREAK				break
#define LEAVE_BLOCK					__leave

#define TRY_START					__try
#define	TRY_FINALLY					__finally
#define TRY_LEAVE					__leave

#define CHK_FAIL_BREAK(dmp) \
{ \
	if (FAILED((hr))) { \
		(dmp); break; \
	} \
}

#define CHK_FALSE_BREAK(value, dmp) \
{ \
	if ((value) == FALSE) { \
		(dmp); break; \
	} \
}

#define CHK_NULL_BREAK(value, dmp) \
{ \
	if ((value) == NULL) { \
		(dmp); break; \
	} \
}

#define CHK_FAIL_LEAVE(dmp) \
{ \
	if (FAILED((hr))) { \
		(dmp); __leave; \
	} \
}

#define CHK_FALSE_LEAVE(value, dmp) \
{ \
	if ((value) == FALSE) { \
		(dmp); __leave; \
	} \
}

#define CHK_NULL_LEAVE(value, dmp) \
{ \
	if ((value) == NULL) { \
		(dmp); __leave; \
	} \
}

enum DotNetVersions {
    DotNet2,
    DotNet3,
    DotNet35,
    DotNet4Client,
    DotNet4Full
};

enum EventCtrlManager {
    EVENT_CTRL_PROCESS,
    EVENT_CTRL_EXIT,
    EVENT_CTRL_COUNT,
};

typedef struct __GenericCommChannel {
    DWORD cbSize;
} GenericCommChannel, *PGenericCommChannel;

typedef struct __InprocComServer {
    wchar_t szFileOld[MAX_PATH];
    wchar_t szFileNew[MAX_PATH];
    wchar_t szDesc[MAX_PATH];
    wchar_t szRPath[MAX_PATH];
    wchar_t szClsid[MAX_PATH];
} InprocComServer, *PInprocComServer;

enum EnumInprocComServer {
    PLUGIN_AVFCONTROL = 0,
    PLUGIN_TOTAL,
};

#define BLACK_YUY2_BUFFER(buffer, size) \
{ \
	PUCHAR pTemp = (PUCHAR)buffer; \
	for (int ctr = 0; ctr < (size); ctr++) \
	{ \
		pTemp[ctr] = (ctr & 1) ? 0x80 : 0x10; \
	} \
}