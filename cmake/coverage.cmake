add_library(coverage INTERFACE)
target_compile_options(coverage INTERFACE
  -Og -g --coverage -fkeep-inline-functions -fkeep-static-functions
)
target_link_options(coverage INTERFACE
  --coverage
)
