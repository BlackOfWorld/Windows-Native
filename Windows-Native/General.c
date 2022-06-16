// NativeLib.cpp : Defines the functions for the static library.
//

#include "framework.h"
#include "General.h"

#include "Native/API/Library.h"
#include "System/Process/Process.h"

struct nativeLib NativeLib;

EXTERNC void NativeInit()
{
	NativeLib.isInitialized = true;
	NativeLib.Process = Process;
	NativeLib.Library = Library;
}