#include "os_util.hpp"

#include <async_ssh.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <string>
#include <string_view>

namespace {
void write_hex_string(std::ostream& oss, std::string_view str) {
  auto flags = oss.flags();
  for (const auto c : str) {
    oss << std::hex << (0xFF & c) << " ";
  }
  oss.flags(flags);
  oss << "\n";
}

std::string read_password() {
  async_ssh::utils::stdin_echo_disabler disable_echo;
  std::string password;
  std::cin >> password;
  return password;
}

} // namespace

int main(int argc, char* argv[]) {
  if (argc !=3) {
    std::cerr << "Usage: " << argv[0] << " host source\n";
    return 1;
  }

  try {
    std::string_view host{argv[1]};
    std::filesystem::path scppath{argv[2]};

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, "ssh");
    async_ssh::session session(io_context);
    boost::asio::connect(session.socket(), endpoints);

    // SSH handshake is required before authentication and any other
    // operations can start
    session.handshake();

    const auto fingerprint = session.hostkey_hash(async_ssh::hostkey_hash_type::sha1);

    std::cout << "Fingerprint: ";
    write_hex_string(std::cout, fingerprint);
    std::cout << "\n";

    const auto homedir = async_ssh::utils::get_home_dir();
    const auto username = async_ssh::utils::get_username();

    const auto pubkey = homedir / ".ssh" / "id_rsa.pub";
    const auto privkey = homedir / ".ssh" / "id_rsa";

    bool authenticated = false;
    if (std::filesystem::exists(pubkey) && std::filesystem::exists(privkey)) {
      try {
        session.public_key_auth(username, pubkey, privkey);
        authenticated = true;
      } catch (const std::exception&) {
        std::cerr << "Authentication by public key failed.\n";
      }
    }

    if (!authenticated) {
      std::cout << username << "@" << host << "'s password: ";
      const auto password = read_password();
      session.password_auth(username, password);
    }

    auto [channel, entry] = session.scp_recv(scppath);
    size_t total_read = 0;
    std::ofstream ofs{scppath.filename()};
    while (total_read < entry.size()) {
      std::array<char, 1024> mem{};
      auto amount = std::min(mem.size(), entry.size() - total_read);
      auto read = boost::asio::read(channel.std_stream(), boost::asio::buffer(mem, amount));
      ofs.write(mem.data(), static_cast<std::streamsize>(read));
      total_read += read;
    }

    // Set the available file permissions
    ofs.close();
    std::filesystem::permissions(scppath.filename(), entry.permissions());

    // Gracefully shutdown the SSH connection
    session.disconnect("Goodbye");
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    std::cerr << "Failed: " << ex.what() << "\n";
    return EXIT_FAILURE;
  }
}
