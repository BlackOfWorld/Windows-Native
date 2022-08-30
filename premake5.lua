-- Copyright (C) 2022 V.
-- For licensing information see LICENSE at the root of this distribution.
require("premake", ">=5.0-beta3")

filter "platforms:Win32"
    architecture "x86"

filter "platforms:x64"
    architecture "x86_64"

filter("architecture:x86_64")
  targetsuffix("64")

filter("language:C++")
  cppdialect("C++20")

filter("language:C")
  cdialect("C17")

filter "configurations:Debug"
    defines { "DEBUG", "_DEBUG" }
    symbols "Full"
    runtime "Debug"
    flags {"Maps"}

filter "configurations:Release"
    defines { "NDEBUG" }
    symbols "Off"
    rtti ("Off")
    optimize "Speed"
    runtime "Release"
    -- staticruntime "on" -- I don't know if this is really worth the file size increase tbh...

workspace("Windows-Native")
  location("./out")
  objdir("./out/link")
  targetdir("./out/bin/%{cfg.platform}")
  libdirs("./out/bin/%{cfg.platform}")

  platforms { "Win32", "x64" }

  configurations({
    "Debug",
    "Release",
  })
  startproject("Test")

  flags({
    "MultiProcessorCompile"
  })

  include("./Windows-Native")
  include("./Test")


