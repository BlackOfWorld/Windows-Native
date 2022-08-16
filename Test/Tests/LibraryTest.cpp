#include "../Framework.h"
#undef LoadLibrary
constexpr int ExportFunc_RetVal = 1337;
extern "C" {
    __declspec(dllexport) int ExportedFunction()
    {
        return ExportFunc_RetVal;
    }
}

TEST(Library, GetFunction)
{
    EXPECT_TRUE(NativeLib.Library.GetFunction) << "GetFunction function does not exist!";
    EXPECT_FALSE(NativeLib.Library.GetFunction(GetModuleHandleW(L"kernel32.dll"), "ThisExportDoesNotExist")) << ERROR_MSG("Non-existent export exists. This should never happen!");
    EXPECT_FALSE(NativeLib.Library.GetFunction(NULL, NULL)) << ERROR_MSG("GetFunction function returned with NULL parameters!");
    EXPECT_EQ(NativeLib.Library.GetFunction(NULL, "ExportedFunction"), &ExportedFunction) << ERROR_MSG("ExportedFunction does not match!");
    EXPECT_EQ(NativeLib.Library.GetFunction(GetModuleHandleW(L"kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA) << ERROR_MSG("SetDllDirectoryA does not match!");
    EXPECT_EQ(NativeLib.Library.GetFunction(NativeLib.Library.GetModule(L"kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA) << ERROR_MSG("SetDllDirectoryA does not match!");
}

TEST(Library, GetFunctionByOrdinal)
{
    EXPECT_TRUE(NativeLib.Library.GetFunctionByOrdinal) << ERROR_MSG("GetFunctionByOrdinal function does not exist!");
    EXPECT_EQ(NativeLib.Library.GetFunctionByOrdinal(NULL, 0), &ExportedFunction) << ERROR_MSG("Failed to find ExportedFunction by Ordinal");
}

TEST(Library, GetModuleFunction)
{
    EXPECT_TRUE(NativeLib.Library.GetModuleFunction) << ERROR_MSG("GetModuleFunction function does not exist!");
    EXPECT_FALSE(NativeLib.Library.GetModuleFunction(L"InvalidDLL.dll", "ExportedFunction")) << ERROR_MSG("Got ExportedFunction from non-existing DLL!");
    EXPECT_FALSE(NativeLib.Library.GetModuleFunction(L"InvalidDLL.dll", "ThisExportDoesNotExist")) << ERROR_MSG("Got something from non-existing DLL!");
    EXPECT_FALSE(NativeLib.Library.GetModuleFunction(L"InvalidDLL.dll", NULL)) << ERROR_MSG("Call with NULL parameter from non-existing DLL succeeded!");
    EXPECT_FALSE(NativeLib.Library.GetModuleFunction(NULL, NULL)) << ERROR_MSG("GetModuleFunction function returned with NULL parameters!");
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"kernel32.dll", "SetDllDirectoryA"), &SetDllDirectoryA) << ERROR_MSG("Failed to get SetDllDirectoryA from kernel32.dll!");
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(NULL, "ExportedFunction"), &ExportedFunction) << ERROR_MSG("Failed to get ExportedFunction with NULL parameter!");
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"", "ExportedFunction"), &ExportedFunction) << ERROR_MSG("Failed to get ExportedFunction with empty parameter!");
    EXPECT_EQ(((decltype(ExportedFunction)*)NativeLib.Library.GetModuleFunction(L"", "ExportedFunction"))(), ExportFunc_RetVal) << ERROR_MSG("ExportedFunction returned different value!");
}
TEST(Library, GetModuleFunctionForwarded)
{
    EXPECT_TRUE(NativeLib.Library.GetModuleFunction) << ERROR_MSG("GetModuleFunction function does not exist!");
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"kernel32.dll", "HeapAlloc"), &HeapAlloc) << ERROR_MSG("Forwarded function HeapAlloc does not match!");
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"advapi32.dll", "EtwEventWrite"), GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "EtwEventWrite")) << ERROR_MSG("Forwarded EtwEventWrite HeapAlloc does not match!");
}
TEST(Library, GetModule)
{
    EXPECT_TRUE(NativeLib.Library.GetModule) << ERROR_MSG("GetModule function does not exist!");
    EXPECT_FALSE(NativeLib.Library.GetModule(L"ThisModuleDoesNotExist.dll")) << ERROR_MSG("Got module that should not exist!");
    EXPECT_EQ(NativeLib.Library.GetModule(nullptr), GetModuleHandleA(nullptr)) << ERROR_MSG("Exe base mismatch!");
    EXPECT_EQ(NativeLib.Library.GetModule(L"kernel32.dll"), GetModuleHandleA("kernel32.dll")) << ERROR_MSG("kernel32 base mismatch!");
}

TEST(Library, LoadLibrary)
{
    SKIP_TEST("Not yet implemented");
}