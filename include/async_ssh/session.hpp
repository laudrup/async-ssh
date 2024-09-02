#ifndef ASYNC_SSH_SESSION_HPP
#define ASYNC_SSH_SESSION_HPP

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>
#include "async_ssh/channel.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace async_ssh {

namespace api = detail::libssh2_api;

/** The session class represents an SSH session that can be used to
 * open one or more SSH channels.
 *
 * @tparam SocketType The type representing the socket used for communication with a remote host.
 * Typically a [boost::asio::ip::tcp::socket](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/ip__tcp/socket.html)
 */
template <class SocketType>
class session {
public:

  /** Construct a session.
   *
   * This constructor creates a session and initialises the underlying
   * socket object.
   *
   *  @param arg The argument to be passed to initialise the
   *  underlying socket object. Typically a [boost::asio::io_context](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/io_context.html)
   */
  template <class Arg>
  explicit session(Arg&& arg)
    : socket_(std::forward<Arg>(arg))
    , session_(api::libssh2_session_init(),
               api::libssh2_session_free) {
    static_assert(std::is_convertible_v<decltype(socket_.native_handle()), libssh2_socket_t>, "Invalid SocketType");
    if (session_ == nullptr) {
      throw std::runtime_error("Unable to allocate libssh2_session");
    }
  }
  session(const session&) = delete;
  session& operator=(const session&) = delete;
  session(session&&) noexcept = default;
  session& operator=(session&&) noexcept = default;

  ~session() {
    if (session_) {
      api::libssh2_session_disconnect(session_.get(), "Goodbye");
    }
  }

  const SocketType& socket() const {
    return socket_;
  }

  SocketType& socket() {
    return socket_;
  }

  LIBSSH2_SESSION* handle() const {
    return session_.get();
  }

  void handshake() {
    const auto rc = api::libssh2_session_handshake(handle(), socket_.native_handle());
    if (rc != 0) {
      throw std::runtime_error("Failure establishing SSH session: " + std::to_string(rc));
    }
  }

  std::string_view hostkey_hash() const {
    const auto hash = api::libssh2_hostkey_hash(handle(), LIBSSH2_HOSTKEY_HASH_SHA1);
    if (hash == nullptr) {
      throw std::runtime_error("Fingerprint unavailable");
    }
    return {hash, 20};
  }

  void public_key_auth(std::string_view username, const std::filesystem::path& pubkey, const std::filesystem::path& privkey) {
    const auto rc = api::libssh2_userauth_publickey_fromfile_ex(handle(),
                                                                username.data(),
                                                                static_cast<unsigned int>(username.size()),
                                                                pubkey.string().c_str(),
                                                                privkey.string().c_str(),
                                                                nullptr);
    if (rc != 0) {
      throw std::runtime_error("Failed public key auth: " + std::to_string(rc));
    }
  }

  void password_auth(std::string_view username, std::string_view password) {
    const auto rc = api::libssh2_userauth_password_ex(handle(),
                                                      username.data(),
                                                      static_cast<unsigned int>(username.size()),
                                                      password.data(),
                                                      static_cast<unsigned int>(password.size()),
                                                      nullptr);
    if (rc != 0) {
      throw std::runtime_error("Failed password auth: " + std::to_string(rc));
    }
  }

  bool authenticated() const {
    return api::libssh2_userauth_authenticated(handle()) == 1;
  }

  std::tuple<async_ssh::channel, libssh2_struct_stat> scp_recv(const std::filesystem::path& path) {
    libssh2_struct_stat fileinfo;
    return {channel{libssh2_scp_recv2(handle(), path.string().c_str(), &fileinfo), handle()}, fileinfo};
  }

private:
  SocketType socket_;
  std::unique_ptr<LIBSSH2_SESSION, decltype(&detail::libssh2_api::libssh2_session_free)> session_;
};

} // namespace async_ssh

#endif // ASYNC_SSH_SESSION_HPP
