-- Copyright (C) 2022 V.
-- For licensing information see LICENSE at the root of this distribution.
require("premake", ">=5.0-beta3")

filter("configurations:32_*")
  architecture("x86")

filter("configurations:64_*")
  architecture("x86_64")

filter("architecture:x86_64 or ARM64")
  targetsuffix("64")

filter("language:C++")
  cppdialect("C++20")

filter("language:C")
  cdialect("C17")

workspace("Windows-Native")
  location("./out")
  objdir("./out/link")
  targetdir("./out/bin/%{cfg.platform}")
  libdirs("./out/bin/%{cfg.platform}")

  configurations({
    "32_Debug",
    "32_Release",
    "64_Debug",
    "64_Release",
  })
  startproject("Test")

  flags({
    "MultiProcessorCompile"
  })

  include("./Windows-Native")
  include("./Test")
  

