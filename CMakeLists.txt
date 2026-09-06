cmake_minimum_required(VERSION 3.16)
project(c-datum-prime C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Werror=implicit-function-declaration)

find_package(PkgConfig)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM libsodium)
endif()

add_executable(c-datum-prime
  src/main.c
  src/framing.c
  src/keys.c
  src/handshake.c
  src/selftest.c
  src/pow.c
  src/mining.c
  src/http_source.c
  src/ledger.c
  src/address.c
  src/abw.c
  src/bulk.c
  src/stats.c
  src/rpc.c
)

target_include_directories(c-datum-prime PRIVATE src)

find_package(Threads REQUIRED)

if(SODIUM_FOUND)
  target_include_directories(c-datum-prime PRIVATE ${SODIUM_INCLUDE_DIRS})
  target_link_libraries(c-datum-prime PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
else()
  target_link_libraries(c-datum-prime PRIVATE sodium Threads::Threads)
endif()
