#pragma once
#include "framework.h"

struct Loader_Module
{
	CHAR* data;
	size_t dataLen;
	wchar_t* dllName;
	wchar_t* cDllName;
	ULONG_PTR moduleBase;
	BOOLEAN linkToPeb;
};

BOOL parseFileName(struct Loader_Module mod, wchar_t* dllName);
