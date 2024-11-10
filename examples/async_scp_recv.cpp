#include "os_util.hpp"

#include <async_ssh.hpp>

#include <boost/asio.hpp>

#include <iostream>
#include <system_error>
#include <utility>

using boost::asio::ip::tcp;

namespace {
std::string read_password() {
  async_ssh::utils::stdin_echo_disabler disable_echo;
  std::string password;
  std::cin >> password;
    return password;
}

} // namespace

class async_scp_client {
public:
  async_scp_client(boost::asio::io_context& io_context,
                   const tcp::resolver::results_type& endpoints,
                   std::filesystem::path path)
      : session_(io_context)
      , path_(std::move(path)) {
    connect(endpoints);
  }

private:
  void connect(const tcp::resolver::results_type& endpoints) {
    boost::asio::async_connect(
        session_.socket(), endpoints, [this](const std::error_code& error,
                                             const tcp::endpoint& /*endpoint*/) {
          if (!error) {
            handshake();
          } else {
            std::cerr << "Connect failed: " << error.message() << "\n";
          }
        });
  }

  void handshake() {
    session_.async_handshake([this](const std::error_code& error) {
      if (!error) {
        public_key_authenticate();
      } else {
        std::cerr << "Handshake failed: " << error.message() << "\n";
      }
    });
  }

  void public_key_authenticate() {
    const auto homedir = async_ssh::utils::get_home_dir();
    const auto username = async_ssh::utils::get_username();

    const auto pubkey = homedir / ".ssh" / "id_rsa.pub";
    const auto privkey = homedir / ".ssh" / "id_rsa";

    if (std::filesystem::exists(pubkey) && std::filesystem::exists(privkey)) {
      std::error_code ec;
      session_.async_public_key_auth(username, pubkey, privkey, [this](const std::error_code& error) {
        if (!error) {
          std::cerr << "Public key auth success!!\n";
          request_file();
        } else {
          std::cerr << "Public key authentication failed: " << error.message() << "\n";
          password_authenticate();
        }
      });
    } else {
      password_authenticate();
    }
  }

  void password_authenticate() {
    const auto username = async_ssh::utils::get_username();
    std::cout << username << "'s password: ";
    const auto password = read_password();
    session_.async_password_auth(username, password, [this](const std::error_code& error) {
      if (!error) {
        request_file();
      } else {
        std::cerr << "Password authentication failed: " << error.message() << "\n";
      }
    });
  }

  void request_file() {
    // Blocking transfer of file contents for now
    auto [channel, entry] = session_.scp_recv(path_);
    size_t total_read = 0;
    while (total_read < entry.size()) {
      std::array<char, 1024> mem{};
      auto read = channel.read_some(boost::asio::buffer(mem));
      std::cout << std::string(mem.data(), mem.size());
      total_read += read;
    }

    // Gracefully shutdown the SSH connection
    session_.disconnect("Goodbye");
  }
  async_ssh::session session_;
  std::filesystem::path path_;
};

int main(int argc, char* argv[]) {
  if (argc !=3) {
    std::cerr << "Usage: " << argv[0] << " host source\n";
    return 1;
  }

  try {
    boost::asio::io_context io_context;

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(argv[1], "ssh");
    std::filesystem::path scppath{argv[2]};

    async_scp_client client(io_context, endpoints, scppath);

    io_context.run();
  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
