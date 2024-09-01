#include "os_util.hpp"

#include <unistd.h>
#include <pwd.h>
#include <termios.h>

namespace async_ssh::utils {
  std::filesystem::path get_home_dir() {
    return getpwuid(getuid())->pw_dir;
  }

  std::string get_username() {
    return getlogin();
  }

  class stdin_echo_disabler::impl {
  public:
    impl() {
      tcgetattr(STDIN_FILENO, &tty_);
      tty_.c_lflag &= ~ECHO;
      tcsetattr(STDIN_FILENO, TCSANOW, &tty_);
    }
    ~impl() {
      tty_.c_lflag |= ECHO;
      tcsetattr(STDIN_FILENO, TCSANOW, &tty_);
    }

  private:
    termios tty_{};
  };

  stdin_echo_disabler::stdin_echo_disabler()
    : impl_(std::make_unique<impl>()) {
  }

  stdin_echo_disabler::~stdin_echo_disabler() = default;

}  // namespace async_ssh::utils

