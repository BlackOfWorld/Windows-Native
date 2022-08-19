project("Test")
  kind("ConsoleApp")
  language("C++")
  nativewchar("Off")
  exceptionhandling("Off")
  floatingpointexceptions("Off")
  intrinsics("on")
  nuget("gmock:1.11.0")
  includedirs({
    ".",
  })
  vpaths {
    ["Tests"] = {"Tests/**.cpp", "Tests/**.h" },
    [""] = { "*.cpp", "*.h", "packages.config" }
  }
  files({
    "**.hint",
    "**.cpp",
    "**.h",
    "packages.config"
  })
  links("LibWindowsNative")