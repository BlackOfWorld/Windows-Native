#pragma once
#include "General.h"

struct MemoryLoad
{
	enum
	{
		LoadFile,
		LoadMemory,
		NoLink
	} flags;
	const wchar_t* dllName;
	PBYTE buffer;
	size_t bufferLen;
};

extern struct Library Library;
