#include "Framework.h"

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    //while (!IsDebuggerPresent()) {}
    DWORD dwModeOut = 0;
    DWORD dwModeIn = 0;

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwModeOut))
        SetConsoleMode(hOut, dwModeOut | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    if(hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &dwModeIn))
        SetConsoleMode(hIn, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS | (dwModeIn & ~ENABLE_QUICK_EDIT_MODE));
    NativeInit();

    const auto testResult = RUN_ALL_TESTS();

    if (hIn != INVALID_HANDLE_VALUE)
        SetConsoleMode(hOut, dwModeOut);
    if (hIn != INVALID_HANDLE_VALUE)
        SetConsoleMode(hIn, dwModeIn);
    return testResult;
}