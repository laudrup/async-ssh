#ifndef ASYNC_SSH_EXAMPLES_OS_UTILS_HPP
#define ASYNC_SSH_EXAMPLES_OS_UTILS_HPP

#include <filesystem>
#include <memory>
#include <string>

namespace async_ssh::utils {
  std::filesystem::path get_home_dir();
  std::string get_username();

  class stdin_echo_disabler {
  public:
    stdin_echo_disabler();
    ~stdin_echo_disabler();
    stdin_echo_disabler(const stdin_echo_disabler&) = delete;
    stdin_echo_disabler& operator=(const stdin_echo_disabler&) = delete;
    stdin_echo_disabler(stdin_echo_disabler&&) noexcept = delete;
    stdin_echo_disabler& operator=(stdin_echo_disabler&&) noexcept = delete;

  private:
    class impl;
    std::unique_ptr<impl> impl_;
  };
}  // namespace async_ssh::utils

#endif
