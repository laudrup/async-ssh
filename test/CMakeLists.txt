cmake_minimum_required(VERSION 3.14)

project(async-ssh-tests LANGUAGES CXX)

Include(FetchContent)

find_package(Patch)
Set(FETCHCONTENT_QUIET FALSE)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.7.0
  GIT_PROGRESS   TRUE
  PATCH_COMMAND ${Patch_EXECUTABLE} --binary -p1 -i ${CMAKE_CURRENT_SOURCE_DIR}/catch2.patch
)

FetchContent_MakeAvailable(Catch2)

FetchContent_Declare(
  Trompeloeil
  GIT_REPOSITORY https://github.com/rollbear/trompeloeil.git
  GIT_TAG        v48
  GIT_PROGRESS   TRUE
)

FetchContent_MakeAvailable(Trompeloeil)

include(../cmake/project-is-top-level.cmake)

if(PROJECT_IS_TOP_LEVEL)
  find_package(async-ssh REQUIRED)
  enable_testing()
endif()

add_executable(unittest
  libssh2_api_mock.cpp
  test_session.cpp
  test_error_codes.cpp
  unittest.cpp
)
target_link_libraries(unittest PRIVATE
  Async::SSH
  Catch2::Catch2
  trompeloeil
  compiler_warnings
)
target_compile_definitions(unittest PRIVATE
  ASYNC_SSH_MOCK_LIBSSH2_API
)
target_compile_features(unittest PRIVATE
  cxx_std_17
)

add_test(NAME unittest COMMAND unittest)
