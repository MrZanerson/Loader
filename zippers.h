#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI picGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI zipGetProcAddress(HMODULE hMod, char * sProcName);
