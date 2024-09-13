add_library(address_sanitizer INTERFACE)
target_compile_options(address_sanitizer INTERFACE
  -fsanitize=address
  -fno-omit-frame-pointer
)

target_link_options(address_sanitizer INTERFACE
  -fsanitize=address
)
