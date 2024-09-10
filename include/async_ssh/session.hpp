#ifndef ASYNC_SSH_SESSION_HPP
#define ASYNC_SSH_SESSION_HPP

#include <async_ssh/channel.hpp>
#include <async_ssh/error.hpp>
#include <async_ssh/remote_directory_entry.hpp>
#include <async_ssh/hostkey_hash_type.hpp>

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>
#include <async_ssh/detail/error.hpp>

#include <filesystem>
#include <memory>
#include <new>
#include <string_view>
#include <system_error>
#include <type_traits>

namespace async_ssh {

namespace detail {
inline size_t hostkey_hash_length(hostkey_hash_type key_type) {
  switch(key_type) {
    case hostkey_hash_type::md5:
      return 16;
    case hostkey_hash_type::sha1:
      return 20;
    case hostkey_hash_type::sha256:
      return 32;
  }
  return 0;
}

} // namespace detail


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
   * compression, and MAC layers.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @see [libssh2_session_handshake](https://libssh2.org/libssh2_session_handshake.html)
   */
  void handshake(std::error_code& ec) {
    const auto rc = api::libssh2_session_handshake(handle(), socket_.native_handle());
    ec = std::error_code(rc, libssh2_error_category());
  }

  /** Perform the SSH handshake.
   *
   * This will trade welcome banners, exchange keys, and setup crypto,
   * compression, and MAC layers.
   *
   * @throws std::system_error Thrown on failure.
   *
   * @see [libssh2_session_handshake](https://libssh2.org/libssh2_session_handshake.html)
   */
  void handshake() {
    std::error_code ec;
    handshake(ec);
    detail::throw_on_error(ec, "handshake");
  }

  /** Return a hash of the remote host's key.
   *
   * Returns the computed digest of the remote system's hostkey.
   *
   * @param hash_type The @ref hostkey_hash_type type of digest to calculate.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @see [libssh2_hostkey_hash](https://libssh2.org/libssh2_hostkey_hash.html)
   */
  std::string_view hostkey_hash(hostkey_hash_type hash_type, std::error_code& ec) const {
    const auto hash = api::libssh2_hostkey_hash(handle(), static_cast<int>(hash_type));
    if (hash == nullptr) {
      ec = errors::hostkey_unavailable;
      return {};
    }
    ec = {};
    return {hash, detail::hostkey_hash_length(hash_type)};
  }

  /** Return a hash of the remote host's key.
   *
   * Returns the computed digest of the remote system's hostkey.
   *
   * @param hash_type The @ref hostkey_hash_type type of digest to calculate.
   *
   * @throws std::system_error Thrown on failure.
   *
   * @see [libssh2_hostkey_hash](https://libssh2.org/libssh2_hostkey_hash.html)
   */
  std::string_view hostkey_hash(hostkey_hash_type hash_type) const {
    std::error_code ec;
    auto fingerprint = hostkey_hash(hash_type, ec);
    detail::throw_on_error(ec, "hostkey_hash");
    return fingerprint;
  }

  /** Authenticate a session with a public key, read from a file
   *
   * @param username The user to authenticate.
   *
   * @param pubkey The path to the public key to use for authenticating the user
   *
   * @param privkey The path to the private key to use for authenticating the user
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @see [libssh2_userauth_publickey_fromfile_ex](https://libssh2.org/libssh2_userauth_publickey_fromfile_ex.html)
   */
  void public_key_auth(std::string_view username, const std::filesystem::path& pubkey,
                       const std::filesystem::path& privkey, std::error_code& ec) {
    const auto rc = api::libssh2_userauth_publickey_fromfile_ex(handle(),
                                                                username.data(),
                                                                static_cast<unsigned int>(username.size()),
                                                                pubkey.string().c_str(),
                                                                privkey.string().c_str(),
                                                                nullptr);
    ec = std::error_code(rc, libssh2_error_category());
  }

  /** Authenticate a session with a public key, read from a file
   *
   * @param username The user to authenticate.
   *
   * @param pubkey The path to the public key to use for authenticating the user
   *
   * @param privkey The path to the private key to use for authenticating the user
   *
   * @throws std::system_error Thrown on failure.
   *
   * @see [libssh2_userauth_publickey_fromfile_ex](https://libssh2.org/libssh2_userauth_publickey_fromfile_ex.html)
   */
  void public_key_auth(std::string_view username, const std::filesystem::path& pubkey,
                       const std::filesystem::path& privkey) {
    std::error_code ec;
    public_key_auth(username, pubkey, privkey, ec);
    detail::throw_on_error(ec, "public_key_auth");
  }

  /** Authenticate a session with a username and password
   *
   * @param username The user to authenticate.
   *
   * @param password Password to use for authenticating username.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @see [libssh2_userauth_password_ex](https://libssh2.org/libssh2_userauth_password_ex.html)
   */
  void password_auth(std::string_view username, std::string_view password, std::error_code& ec) {
    const auto rc = api::libssh2_userauth_password_ex(handle(),
                                                      username.data(),
                                                      static_cast<unsigned int>(username.size()),
                                                      password.data(),
                                                      static_cast<unsigned int>(password.size()),
                                                      nullptr);
    ec = std::error_code(rc, libssh2_error_category());
  }

  /** Authenticate a session with a username and password
   *
   * @param username The user to authenticate.
   *
   * @param password Password to use for authenticating username.
   *
   * @throws std::system_error Thrown on failure.
   *
   * @see [libssh2_userauth_password_ex](https://libssh2.org/libssh2_userauth_password_ex.html)
   */
  void password_auth(std::string_view username, std::string_view password) {
    std::error_code ec;
    password_auth(username, password, ec);
    detail::throw_on_error(ec, "password_auth");
  }

  /** Request a remote file via SCP
   *
   * @param path The path of the remote file
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @return A channel for getting the file data and an entry with
   * status on the remote file.
   *
   * @see [libssh2_scp_recv2](https://libssh2.org/libssh2_scp_recv2.html)
   */
  std::tuple<async_ssh::channel, async_ssh::remote_directory_entry> scp_recv(const std::filesystem::path& path, std::error_code& ec) {
    remote_directory_entry entry{};
    LIBSSH2_CHANNEL* chan = api::libssh2_scp_recv2(handle(), path.string().c_str(), &entry.stat_);
    if (chan == nullptr) {
      ec = std::error_code(api::libssh2_session_last_errno(handle()), libssh2_error_category());
    } else {
      ec = {};
    }
    return {channel{chan}, entry};
  }

  /** Request a remote file via SCP
   *
   * @param path The path of the remote file
   *
   * @return A channel for getting the file data and an entry with
   * status on the remote file.
   *
   * @throws std::system_error Thrown on failure.
   *
   * @see [libssh2_scp_recv2](https://libssh2.org/libssh2_scp_recv2.html)
   */
  std::tuple<async_ssh::channel, async_ssh::remote_directory_entry> scp_recv(const std::filesystem::path& path) {
    std::error_code ec;
    std::tuple<async_ssh::channel, async_ssh::remote_directory_entry> ret = scp_recv(path, ec);
    detail::throw_on_error(ec, "scp_recv");
    return ret;
  }

private:
  SocketType socket_;
  std::unique_ptr<LIBSSH2_SESSION, decltype(&detail::libssh2_api::libssh2_session_free)> session_;
};

} // namespace async_ssh

#endif // ASYNC_SSH_SESSION_HPP
