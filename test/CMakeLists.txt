cmake_minimum_required(VERSION 3.14)

project(async-ssh-tests LANGUAGES CXX)

include(../cmake/project-is-top-level.cmake)
include(../cmake/compiler-warnings.cmake)

if(PROJECT_IS_TOP_LEVEL)
  find_package(async-ssh REQUIRED)
  enable_testing()
endif()

add_executable(unittest
  unittest.cpp
)
target_link_libraries(unittest PRIVATE
  Async::SSH
  compiler_warnings
)
target_compile_features(unittest PRIVATE
  cxx_std_17
)

add_test(NAME unittest COMMAND unittest)
