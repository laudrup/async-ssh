#include <async_ssh.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

#include <unistd.h>
#include <pwd.h>
#include <termios.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

namespace {
  void write_hex_string(std::ostream& oss, std::string_view str) {
    auto flags = oss.flags();
    for (const auto c : str) {
      oss << std::hex << static_cast<int>(0xFF & c) << " ";
    }
    oss.flags(flags);
    oss << "\n";
  }

  std::string_view get_home_dir() {
    return getpwuid(getuid())->pw_dir;
  }

  std::string_view get_username() {
    return getlogin();
  }

  void stdin_echo(bool enable) {
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    if(enable) {
      mode |= ENABLE_ECHO_INPUT;
    } else {
      mode &= ~ENABLE_ECHO_INPUT;
    }
    SetConsoleMode(hStdin, mode);
#else
    termios tty{};
    tcgetattr(STDIN_FILENO, &tty);
    if(enable) {
      tty.c_lflag |= ECHO;
    } else {
      tty.c_lflag &= ~ECHO;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
  };

  std::string read_password() {
    std::string password;
    stdin_echo(false);
    std::cin >> password;
    stdin_echo(true);
    return password;
  }
} // namespace

int main(int argc, char* argv[]) {
  if (argc !=3) {
    std::cerr << "Usage: " << argv[0] << " host source\n";
    return 1;
  }

  std::string_view host{argv[1]};
  std::filesystem::path scppath{argv[2]};

  boost::asio::io_context io_context;
  boost::asio::ip::tcp::resolver resolver(io_context);
  boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, "ssh");
  async_ssh::session<boost::asio::ip::tcp::socket> session(io_context);
  boost::asio::connect(session.socket(), endpoints);

  session.handshake();

  const auto fingerprint = session.hostkey_hash();
  std::cerr << "Fingerprint: ";
  write_hex_string(std::cerr, fingerprint);

  const auto pubkey = std::filesystem::path{get_home_dir()} / ".ssh" / "id_rsa.pub";
  const auto privkey = std::filesystem::path{get_home_dir()} / ".ssh" / "id_rsa";
  bool authenticated = false;
  if (std::filesystem::exists(pubkey) && std::filesystem::exists(privkey)) {
    try {
      session.public_key_auth(get_username(), pubkey, privkey);
      authenticated = true;
    } catch (const std::exception& ex) {
      std::cerr << "Authentication by public key failed.\n";
    }
  }

  if (!authenticated) {
    std::cout << get_username() << "@" << host << "'s password: ";
    const auto password = read_password();
    session.password_auth(get_username(), password);
  }

  /* Request a file via SCP */
  //libssh2_struct_stat fileinfo;
  //async_ssh::channel channel(libssh2_scp_recv2(session.handle(), scppath.c_str(), &fileinfo), session.handle());
  /*
  fprintf(stdout, "Links\tUid\tGid\tSize\tMode\tName\n");
  fprintf(stdout, "%u\t%u\t%u\t%u\t%u\t%s\n", fileinfo.st_nlink,
          fileinfo.st_uid, fileinfo.st_gid, fileinfo.st_size, fileinfo.st_mode,
          scppath.c_str());
  */
  auto [channel, fileinfo] = session.scp_recv(scppath);
  size_t total_read = 0;
  while (total_read < fileinfo.st_size) {
    std::array<char, 1024> mem{};
    auto read = channel.read_some(boost::asio::buffer(mem));
    if (read > 0) {
      std::cout << std::string(mem.data(), mem.size());
    }
    total_read += read;
  }

  return 0;
}
