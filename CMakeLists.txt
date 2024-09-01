cmake_minimum_required(VERSION 3.14)

include(cmake/prelude.cmake)
include(cmake/version-from-git.cmake)

version_from_git()

project(
  async-ssh
  VERSION ${VERSION}
  DESCRIPTION "A C++17 SSH client using Asio and libssh2"
  HOMEPAGE_URL "https://github.com/laudrup/async-ssh"
  LANGUAGES CXX
)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
find_package(Libssh2 REQUIRED)
find_package(Boost CONFIG REQUIRED)

include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

add_library(async_ssh INTERFACE)
add_library(Async::SSH ALIAS async_ssh)

set_property(
  TARGET async-ssh PROPERTY
  EXPORT_NAME SSH
)

target_include_directories(
  async-ssh ${warning_guard}
  INTERFACE
  "\$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
)

target_compile_features(async_ssh INTERFACE cxx_std_17)

target_link_libraries(async_ssh INTERFACE
  libssh2::libssh2
  Boost::headers
)

if(NOT CMAKE_SKIP_INSTALL_RULES)
  include(cmake/install-rules.cmake)
endif()

if(BUILD_TESTING)
  include(CTest)
  add_subdirectory(test)
endif()

if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
