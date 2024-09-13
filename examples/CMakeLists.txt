add_executable(scp scp.cpp)
target_link_libraries(scp PRIVATE
  async_ssh
  compiler_warnings
)
target_compile_features(scp PRIVATE cxx_std_17)

if(WIN32)
  target_sources(scp PRIVATE os_util_win32.cpp)
  target_link_libraries(scp PRIVATE userenv)
else()
  target_sources(scp PRIVATE os_util_posix.cpp)
endif()

if(ENABLE_ADDRESS_SANITIZER)
  target_link_libraries(scp PRIVATE
    address_sanitizer
  )
endif()
