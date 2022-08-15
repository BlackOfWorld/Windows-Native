#include "../Framework.h"

TEST(File, Create)
{
    EXPECT_NE(NativeLib.File.Create((wchar_t*)L"TestFile.txt", FILE_GENERIC_WRITE, FILE_SHARE_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL), INVALID_HANDLE_VALUE);
}

TEST(File, Size)
{
    EXPECT_TRUE(NativeLib.File.Size);
    EXPECT_EQ(NativeLib.File.Size(nullptr), INVALID_FILE_SIZE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
}