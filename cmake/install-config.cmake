include("${CMAKE_CURRENT_LIST_DIR}/async-sshTargets.cmake")

include(CMakeFindDependencyMacro)
find_dependency(Boost)
find_dependency(Libssh2)
