#include <Native/API/Loader.h>

BOOL parseFileName(struct Loader_Module mod, wchar_t* dllName)
{
	if (!dllName) return false;
	mod.dllName = dllName;
	mod.cDllName = malloc(69);
}
