project("LibWindowsNative")
  targetname("Windows-Native")
  kind("StaticLib")
  language("C")
  nativewchar("Off")
  exceptionhandling("Off")
  floatingpointexceptions("Off")
  intrinsics("on")
  linkoptions {"/NODEFAULTLIB"}

  filter { "toolset:msc*" }
    disablewarnings { "4312" }

  flags({
    "NoBufferSecurityCheck"
  })
  includedirs({
    ".",
  })
  files({
    "**.hint",
    "**.c",
    "**.h",
  })