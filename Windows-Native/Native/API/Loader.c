#include <Native/API/Loader.h>

#include "General.h"

// https://doxygen.reactos.org/de/dff/dll_2win32_2shlwapi_2path_8c.html#a4f5d0600b29071eb05db54baccb18e0b
LPWSTR PathFindFileNameW(LPWSTR lpszPath)
{
	LPWSTR lastSlash = lpszPath;

	while (lpszPath && *lpszPath)
	{
		if ((*lpszPath == '\\' || *lpszPath == '/' || *lpszPath == ':') &&
			lpszPath[1] && lpszPath[1] != '\\' && lpszPath[1] != '/')
			lastSlash = lpszPath + 1;
		lpszPath++;
	}
	return lastSlash;
}

BOOL parseFileName(struct Loader_Module mod, wchar_t* dllName)
{
	if (!dllName) return false;
	mod.dllName = dllName;
	mod.cDllName = NativeLib.Memory.Allocate(MAX_PATH * 2, TRUE);
	if (!mod.cDllName) { __debugbreak();  return FALSE; } // No memory?
	LPWSTR fileName = PathFindFileNameW(dllName);
	wstrcpy(mod.cDllName, fileName);
	return TRUE;
}

