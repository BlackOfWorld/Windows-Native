// NativeLib.cpp : Defines the functions for the static library.
//

#include "framework.h"
#include "General.h"

#include "Native/API/Library.h"
#include "System/Process/Process.h"
#include "Memory/Memory.h"

struct nativeLib NativeLib;

EXTERNC void NativeInit()
{
	NativeLib.isInitialized = true;
	NativeLib.Process = Process;
	NativeLib.Library = Library;
	NativeLib.Memory = Memory;
	cpu_detect_features();
}