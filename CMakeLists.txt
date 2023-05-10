cmake_minimum_required(VERSION 3.16)
project(OpenSSL_Provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_INSTALL_PREFIX "C:/Program Files/OpenSSL/lib")
set(CMAKE_FIND_DEBUG_MODE ON)

add_link_options("/NODEFAULTLIB:MSVCRT")
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL/")
find_package(OpenSSL REQUIRED)

set(LINK_LIBS OpenSSL::SSL OpenSSL::Crypto crypt32.lib ws2_32.lib ncrypt.lib)
add_subdirectory(cng_provider)
add_subdirectory(client)


# do not use add_compile_options, include_directories, link_directories, link_libraries as they are dir level commands

