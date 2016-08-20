/*
* Copyright(c) 2016 Chew Esmero
* All rights reserved.
*/

#include "stdafx.h"
#include "../include/libcore.h"

_declspec(dllexport) LSTATUS ReadBin32(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, BYTE *pData, DWORD *pcbData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_32KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, NULL, NULL, pData, pcbData);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadBin64(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, BYTE *pData, DWORD *pcbData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, NULL, NULL, pData, pcbData);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadBinAuto(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, BYTE *pData, DWORD *pcbData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, NULL, NULL, pData, pcbData);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteBin32(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, BYTE *pData, DWORD cbData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS | KEY_WOW64_32KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_BINARY, pData, cbData);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteBin64(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, BYTE *pData, DWORD cbData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS | KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_BINARY, pData, cbData);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteBinAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, BYTE *pData, DWORD cbData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_BINARY, pData, cbData);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadDword32(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, DWORD *pdwData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD cbSize = sizeof(DWORD);
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_32KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, NULL, NULL, (LPBYTE)pdwData, &cbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadDword64(HKEY hKeyRoot, TCHAR *pszKey, TCHAR *pszName, DWORD *pdwData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD cbSize = sizeof(DWORD);
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, NULL, NULL, (LPBYTE)pdwData, &cbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadDwordAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD *pdwData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD cbSize = sizeof(DWORD);
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, NULL, NULL, (LPBYTE)pdwData, &cbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteDword32(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD dwData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS | KEY_WOW64_32KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_DWORD, (LPBYTE)&dwData, sizeof(DWORD));

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteDword64(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD dwData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS | KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_DWORD, (LPBYTE)&dwData, sizeof(DWORD));

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteDwordAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, DWORD dwData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_DWORD, (LPBYTE)&dwData, sizeof(DWORD));

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadSz32(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwType = REG_SZ;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_32KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, 0, &dwType, (LPBYTE)pszData, pcbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwType = REG_SZ;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, 0, &dwType, (LPBYTE)pszData, pcbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteSz32(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, wchar_t *pszData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS | KEY_WOW64_32KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_SZ, (LPBYTE)pszData, lstrlen(pszData) * sizeof(wchar_t));

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteSz64(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, wchar_t *pszData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS | KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_SZ, (LPBYTE)pszData, lstrlen(pszData) * sizeof(wchar_t));

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteSzAuto(HKEY hKeyRoot, wchar_t *pszKey, wchar_t *pszName, wchar_t *pszData)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_SZ, (LPBYTE)pszData, lstrlen(pszData) * sizeof(wchar_t));

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadMultiSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwType = REG_MULTI_SZ;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, 0, &dwType, (LPBYTE)pszData, pcbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS WriteMultiSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, DWORD cbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDisposition;
    REGSAM sam = KEY_ALL_ACCESS;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegCreateKeyEx(hKeyRoot, pszKey, 0, NULL, 0, sam, NULL, &hKey, &dwDisposition);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegSetValueEx(hKey, pszName, 0, REG_MULTI_SZ, (LPBYTE)pszData, cbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadExpandSz32(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwType = REG_EXPAND_SZ;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_32KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, 0, &dwType, (LPBYTE)pszData, pcbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadExpandSz64(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwType = REG_EXPAND_SZ;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ | KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, 0, &dwType, (LPBYTE)pszData, pcbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}

_declspec(dllexport) LSTATUS ReadExpandSzAuto(HKEY hKeyRoot, wchar_t* pszKey, wchar_t *pszName, wchar_t *pszData, LPDWORD pcbSize)
{
    LSTATUS lStatus = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwType = REG_EXPAND_SZ;
    REGSAM sam = KEY_QUERY_VALUE | KEY_READ;

    if (IsWow64() == TRUE) sam |= KEY_WOW64_64KEY;

    lStatus = RegOpenKeyEx(hKeyRoot, pszKey, 0, sam, &hKey);

    if (lStatus == ERROR_SUCCESS)
    {
        lStatus = RegQueryValueEx(hKey, pszName, 0, &dwType, (LPBYTE)pszData, pcbSize);

        RegCloseKey(hKey);
    }

    return lStatus;
}
