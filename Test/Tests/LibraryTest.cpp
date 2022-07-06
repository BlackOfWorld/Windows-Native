#include "../Framework.h"
#undef LoadLibrary

extern "C" {
	__declspec(dllexport) int ExportedFunction()
	{
		return 1337;
	}
}

TEST(Library, GetFunction)
{
	EXPECT_TRUE(NativeLib.Library.GetFunction);
	EXPECT_FALSE(NativeLib.Library.GetFunction(GetModuleHandleW(L"kernel32.dll"), "ThisExportDoesNotExist"));
	EXPECT_FALSE(NativeLib.Library.GetFunction(NULL, NULL));
	EXPECT_EQ(NativeLib.Library.GetFunction(NULL, "ExportedFunction"), &ExportedFunction);
	EXPECT_EQ(NativeLib.Library.GetFunction(GetModuleHandleW(L"kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA);
	EXPECT_EQ(NativeLib.Library.GetFunction(NativeLib.Library.GetModule(L"kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA);
}

TEST(Library, GetFunctionByOrdinal)
{
	EXPECT_EQ(NativeLib.Library.GetFunctionByOrdinal(NULL, 0), &ExportedFunction);
}

TEST(Library, GetModuleFunction)
{
	EXPECT_TRUE(NativeLib.Library.GetModuleFunction);
	EXPECT_FALSE(NativeLib.Library.GetModuleFunction(L"InvalidDLL.dll", "ExportedFunction"));
	EXPECT_FALSE(NativeLib.Library.GetModuleFunction(L"InvalidDLL.dll", "ThisExportDoesNotExist"));
	EXPECT_FALSE(NativeLib.Library.GetModuleFunction(L"InvalidDLL.dll", NULL));
	EXPECT_FALSE(NativeLib.Library.GetModuleFunction(NULL, NULL));
	EXPECT_EQ(NativeLib.Library.GetModuleFunction(NULL, "ExportedFunction"), &ExportedFunction);
	EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"", "ExportedFunction"), &ExportedFunction);
	EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"kernel32.dll", "SetDllDirectoryA"), &SetDllDirectoryA);
}
TEST(Library, GetModuleFunctionForwarded)
{
	EXPECT_TRUE(NativeLib.Library.GetModuleFunction);
	EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"kernel32.dll", "HeapAlloc"), &HeapAlloc);
	EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"advapi32.dll", "EtwEventWrite"), GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "EtwEventWrite"));
}
TEST(Library, GetModule)
{
	EXPECT_TRUE(NativeLib.Library.GetModule);
	EXPECT_FALSE(NativeLib.Library.GetModule(L"ThisModuleDoesNotExist.dll"));
	EXPECT_EQ(NativeLib.Library.GetModule(nullptr), GetModuleHandleA(nullptr));
	EXPECT_EQ(NativeLib.Library.GetModule(L"kernel32.dll"), GetModuleHandleA("kernel32.dll"));
}

TEST(Library, LoadLibrary)
{
	GTEST_SKIP("Not yet implemented");
}