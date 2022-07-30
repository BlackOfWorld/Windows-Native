#pragma once
#define ERROR_MSG(msg) "\033[41;1m" msg "\033[0;0m"
#define SKIP_TEST(msg) GTEST_SKIP_("\033[44;1m" msg "\033[0;0m")
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <Windows.h>
extern "C" {
#include "../Windows-Native/General.h"
}
