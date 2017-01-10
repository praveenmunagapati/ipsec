workspace "Penguin"
configurations { "Release" }

configurations "Release"
flags { "Optimize" }

language "C"
warnings "Extra"
buildoptions { "-DLINUX -DDEBUG -std=gnu99", "-mcmodel=large", "-Wno-unused", "-Wno-format", "-Wno-unused-result" }

project "Manager"

kind "ConsoleApp"

location "build"
targetname "sad_accessor"
targetdir "."
files { "src/**.h", "src/**.c" }
includedirs { "/home/sungho/Project/penguin/include", "/home/sungho/Project/manager/lib/include", "./include", "../../include" }
libdirs { "/home/sungho/Project/manager", "/home/sungho/Project/manager/lib" }
links { "umpn", "pn_assistant", "rt" }
