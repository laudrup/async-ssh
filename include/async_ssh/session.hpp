#ifndef ASYNC_SSH_SESSION_HPP
#define ASYNC_SSH_SESSION_HPP

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>
#include <async_ssh/channel.hpp>
#include <async_ssh/detail/error.hpp>

#include <filesystem>
#include <memory>
#include <new>
#include <stdexcept>
#include <string_view>
#include <system_error>
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
   *
   * @see [libssh2_session_init](https://libssh2.org/libssh2_session_init.html)
   *
   * @throws std::bad_alloc On storage allocation failures.
   */
  template <class Arg>
  explicit session(Arg&& arg)
    : socket_(std::forward<Arg>(arg))
    , session_(api::libssh2_session_init(),
               api::libssh2_session_free) {
    static_assert(std::is_convertible_v<decltype(socket_.native_handle()), libssh2_socket_t>, "Invalid SocketType");
    if (session_ == nullptr) {
      throw std::bad_alloc{};
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

  /** Get a reference to the socket being used for communication with
   * the server.
   *
   * @return A reference to the socket. Ownership is not transferred
   * to the caller.
   */
  const SocketType& socket() const {
    return socket_;
  }

  /** Get a reference to the socket being used for communication with
   * the server.
   *
   * @return A reference to the socket. Ownership is not transferred
   * to the caller.
   */
  SocketType& socket() {
    return socket_;
  }

  /** Get a pointer to the libssh2 session being used by this object.
   *
   * @see [libssh2 docs](https://libssh2.org/docs.html)
   *
   * @return A pointer to the libssh2 session. Ownership is not
   * transferred to the caller.
   */
  LIBSSH2_SESSION* handle() const {
    return session_.get();
  }

  /** Perform the SSH handshake.
   *
   * This will trade welcome banners, exchange keys, and setup crypto,
   * compression, and MAC layers
   *
   * @see [libssh2_session_handshake](https://libssh2.org/libssh2_session_handshake.html)
   *
   * @param ec Set to indicate what error occurred, if any.
   */
  void handshake(std::error_code& ec) {
    const auto rc = api::libssh2_session_handshake(handle(), socket_.native_handle());
    ec = make_error_code(rc);
  }

  /** Perform the SSH handshake.
   *
   * This will trade welcome banners, exchange keys, and setup crypto,
   * compression, and MAC layers
   *
   * @see [libssh2_session_handshake](https://libssh2.org/libssh2_session_handshake.html)
   *
   * @throws std::system_error Thrown on failure.
   */
  void handshake() {
    std::error_code ec;
    handshake(ec);
    detail::throw_on_error(ec);
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
