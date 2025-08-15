set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR xtensa)

set(CMAKE_C_COMPILER xtensa-esp32-elf-gcc)
set(CMAKE_CXX_COMPILER xtensa-esp32-elf-g++)
set(CMAKE_ASM_COMPILER xtensa-esp32-elf-gcc)
set(CMAKE_AR xtensa-esp32-elf-ar)
set(CMAKE_RANLIB xtensa-esp32-elf-ranlib)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_FLAGS_INIT "-mlongcalls -ffunction-sections -fdata-sections -fno-lto")
set(CMAKE_CXX_FLAGS_INIT "-mlongcalls -ffunction-sections -fdata-sections -fno-lto -fno-rtti -fno-exceptions")

