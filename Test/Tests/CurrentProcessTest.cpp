#include "../Framework.h"

TEST(CurrentProcess, DetectDebugger)
{
    SKIP_TEST("Skipping for Github actions, for now...");
    EXPECT_EQ(NativeLib.Process.CurrentProcess.DetectDebugger(), IsDebuggerPresent()) << "Failed to detect debugger! Are you running AntiAntiDebug?";
}
TEST(CurrentProcess, GetCurrentId)
{
    EXPECT_EQ(NativeLib.Process.CurrentProcess.GetCurrentId(), GetCurrentProcessId()) << "Current process ID does not match! Maybe PEB is misaligned?";
}