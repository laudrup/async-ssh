add_executable(scp scp.cpp)
target_link_libraries(scp PRIVATE async-ssh::async-ssh)
target_compile_features(scp PRIVATE cxx_std_17)
