#include "os_util.hpp"

#include <lmcons.h>
#include <userenv.h>
#include <windows.h>

#include <array>

namespace async_ssh::utils {
  std::filesystem::path get_home_dir() {
    HANDLE handle = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &handle);
    std::array<char, MAX_PATH> userdir;
    auto size = static_cast<DWORD>(userdir.size());
    GetUserProfileDirectoryA(handle, userdir.data(), &size);
    CloseHandle(handle);
    return {userdir.data(), static_cast<size_t>(size)};
  }

  std::string get_username() {
    std::array<char, UNLEN+1> username;
    auto size = static_cast<DWORD>(username.size());
    GetUserNameA(username.data(), &size);
    return {username.data(), static_cast<size_t>(size)};
  }

  class stdin_echo_disabler::impl {
  public:
    impl()
      : stdin_handle_(GetStdHandle(STD_INPUT_HANDLE)) {
      GetConsoleMode(stdin_handle_, &mode_);
      mode_ &= ~ENABLE_ECHO_INPUT;
      SetConsoleMode(stdin_handle_, mode_);
    }

    ~impl() {
      mode_ |= ENABLE_ECHO_INPUT;
      SetConsoleMode(stdin_handle_, mode_);
    }

  private:
    HANDLE stdin_handle_;
    DWORD mode_;
  };

  stdin_echo_disabler::stdin_echo_disabler()
    : impl_(std::make_unique<impl>()) {
  }

  stdin_echo_disabler::~stdin_echo_disabler() = default;
}  // namespace async_ssh::utils

