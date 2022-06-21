#pragma once
#include "framework.h"

struct Memory
{
	HANDLE(*GetCurrentHeap)();
	HANDLE(*GetCurrentHeaps)();
};

extern struct Memory Memory;
