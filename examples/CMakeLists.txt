function(add_example target)
  add_executable(${target} ${target}.cpp)
  target_link_libraries(${target} PRIVATE
    async_ssh
    compiler_warnings
  )
  target_compile_features(${target} PRIVATE cxx_std_17)

  if(WIN32)
    target_sources(${target} PRIVATE os_util_win32.cpp)
    target_link_libraries(${target} PRIVATE userenv)
  else()
    target_sources(${target} PRIVATE os_util_posix.cpp)
  endif()

  if(ENABLE_ADDRESS_SANITIZER)
    target_link_libraries(${target} PRIVATE address_sanitizer)
  endif()
endfunction()

set(examples
  scp_recv
  async_scp_recv
)

foreach(target ${examples})
  add_example(${target})
endforeach()
