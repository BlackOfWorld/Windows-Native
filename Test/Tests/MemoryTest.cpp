#include "../Framework.h"
TEST(Memory, GetCurrentHeap)
{
	EXPECT_TRUE(NativeLib.Memory.GetCurrentHeap);
	EXPECT_EQ(NativeLib.Memory.GetCurrentHeap(), GetProcessHeap());
}
