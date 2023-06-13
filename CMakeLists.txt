cmake_minimum_required(VERSION 3.16)
project(OpenSSL_Provider C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_INSTALL_PREFIX "C:/Program Files/OpenSSL/lib")
set(CMAKE_FIND_DEBUG_MODE ON)

if(WIN32)
  # Unfortunately, FindOpenSSL.cmake doesn't give satisfactory results
  # on Windows.  It adds the OpenSSL libraries with the type UNKNOWN,
  # which excludes any possibility to declare the associated DLL.
  # This means that for any application or module that's linked with
  # the export libraries for those DLLs, those DLLs must be copied
  # manually alongside those applications and modules (and you must
  # figure out the DLL name on your own).
  # It's simpler to link with static OpenSSL libraries and not deal
  # with their DLLs at all.
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL/")
find_package(OpenSSL 3.0 REQUIRED)

add_subdirectory(cng_provider)
add_subdirectory(client)


# do not use add_compile_options, include_directories, link_directories, link_libraries as they are dir level commands

