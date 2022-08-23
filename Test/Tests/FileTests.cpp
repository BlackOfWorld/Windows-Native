#include "../Framework.h"

TEST(File, Create)
{
    EXPECT_EQ(NativeLib.File.Create(L"\0", 0, 0, 0, 0), INVALID_HANDLE_VALUE);
    HANDLE hFile = NativeLib.File.Create(L"TestFile.txt", FILE_GENERIC_WRITE, FILE_SHARE_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    EXPECT_NE(hFile, INVALID_HANDLE_VALUE);
    EXPECT_EQ(NativeLib.File.Close(hFile), true);
}

TEST(File, Size)
{
    EXPECT_TRUE(NativeLib.File.Size);
    EXPECT_EQ(NativeLib.File.Size(nullptr), INVALID_FILE_SIZE);
    EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
}