cmake_minimum_required(VERSION 3.14)

project(async-ssh-tests LANGUAGES CXX)

Include(FetchContent)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
set(FETCHCONTENT_QUIET FALSE)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.7.1
  GIT_PROGRESS   TRUE
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
  test_authentication.cpp
  test_channel.cpp
  test_error_codes.cpp
  test_handshake.cpp
  test_scp.cpp
  test_session.cpp
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
  CATCH_CONFIG_ENABLE_ALL_STRINGMAKERS
)
target_compile_features(unittest PRIVATE
  cxx_std_17
)

if(ENABLE_COVERAGE)
  target_link_libraries(unittest PRIVATE
    coverage
  )
endif()

if(ENABLE_ADDRESS_SANITIZER)
  target_link_libraries(unittest PRIVATE
    address_sanitizer
  )
endif()

add_test(NAME unittest COMMAND unittest)
