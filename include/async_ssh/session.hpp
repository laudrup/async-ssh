#ifndef ASYNC_SSH_SESSION_HPP
#define ASYNC_SSH_SESSION_HPP

#include <async_ssh/channel.hpp>
#include <async_ssh/error.hpp>
#include <async_ssh/remote_directory_entry.hpp>
#include <async_ssh/hostkey_hash_type.hpp>

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>
#include <async_ssh/detail/async_handshake.hpp>
#include <async_ssh/detail/async_public_key_auth.hpp>
#include <async_ssh/detail/async_password_auth.hpp>
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
 * @tparam Socket The type representing the socket used for communication with a remote host.
 * Typically a [boost::asio::ip::tcp::socket](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/ip__tcp/socket.html)
 */
template <class Socket>
class session {
public:
  /// The type of the next layer.
  using socket_type = typename std::remove_reference<Socket>::type;

  /// The type of the executor associated with the object.
  using executor_type = typename std::remove_reference<socket_type>::type::executor_type;

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
    static_assert(std::is_convertible_v<decltype(socket_.native_handle()), libssh2_socket_t>, "Invalid Socket");
    if (!session_) {
      throw std::bad_alloc{};
    }
  }
  session(const session&) = delete;
  session& operator=(const session&) = delete;
  session(session&&) noexcept = default;
  session& operator=(session&&) noexcept = default;

  /** Get the executor associated with the object.
   *
   * This function may be used to obtain the executor object that the
   * stream uses to dispatch handlers for asynchronous operations.
   *
   * @return A copy of the executor that stream will use to dispatch
   * handlers.
   */
  executor_type get_executor() {
    return socket().get_executor();
  }

  /** Get a reference to the socket being used for communication with
   * the server.
   *
   * @return A reference to the socket. Ownership is not transferred
   * to the caller.
   */
  const socket_type& socket() const {
    return socket_;
  }

  /** Get a reference to the socket being used for communication with
   * the server.
   *
   * @return A reference to the socket. Ownership is not transferred
   * to the caller.
   */
  socket_type& socket() {
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
   * compression, and MAC layers. The function call will block until
   * handshaking is complete or an error occurs.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @see [libssh2_session_handshake](https://libssh2.org/libssh2_session_handshake.html)
   */
  void handshake(std::error_code& ec) {
    ec = do_blocking_call(api::libssh2_session_handshake, socket_.native_handle());
  }

  /** Perform the SSH handshake.
   *
   * This will trade welcome banners, exchange keys, and setup crypto,
   * compression, and MAC layers. The function call will block until
   * handshaking is complete or an error occurs.
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

  /** Perform the SSH handshake.
   *
   * This will trade welcome banners, exchange keys, and setup crypto,
   * compression, and MAC layers. This function call always returns
   * immediately.
   *
   * @param handler The handler to be called when the operation
   * completes. The implementation takes ownership of the handler by
   * performing a decay-copy. The handler must be invocable with this
   * signature:
   * @code
   * void handler(
   *     const std::error_code& // Result of operation.
   * );
   * @endcode
   *
   * @note Regardless of whether the asynchronous operation completes
   * immediately or not, the handler will not be invoked from within
   * this function. Invocation of the handler will be performed in a
   * manner equivalent to using `net::post`.
   *
   * @see [libssh2_session_handshake](https://libssh2.org/libssh2_session_handshake.html)
   */
  template <class CompletionToken>
  auto async_handshake(CompletionToken&& handler) {
    return boost::asio::async_compose<CompletionToken, void(const std::error_code&)>(
      detail::async_handshake<socket_type>{socket_, session_.get()}, handler, get_executor());
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
   * The function call will block until the session has been
   * authenticated or an error occurs.
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
    ec = do_blocking_call(api::libssh2_userauth_publickey_fromfile_ex,
                          username.data(),
                          static_cast<unsigned int>(username.size()),
                          pubkey.string().c_str(),
                          privkey.string().c_str(),
                          nullptr);
  }

  /** Authenticate a session with a public key, read from a file
   *
   * The function call will block until the session has been
   * authenticated or an error occurs.
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

  /** Authenticate a session with a public key, read from a file
   *
   * This function call always returns immediately.
   *
   * @param username The user to authenticate. The implementation will
   * keep a copy of this argument.
   *
   * @param pubkey The path to the public key to use for
   * authenticating the user. The implementation will keep a copy of
   * this argument.
   *
   * @param privkey The path to the private key to use for
   * authenticating the user. The implementation will keep a copy of
   * this argument.
   *
   * @param handler The handler to be called when the operation
   * completes. The implementation takes ownership of the handler by
   * performing a decay-copy. The handler must be invocable with this
   * signature:
   * @code
   * void handler(
   *     const std::error_code& // Result of operation.
   * );
   * @endcode
   *
   * @note Regardless of whether the asynchronous operation completes
   * immediately or not, the handler will not be invoked from within
   * this function. Invocation of the handler will be performed in a
   * manner equivalent to using `net::post`.
   *
   * @see [libssh2_userauth_publickey_fromfile_ex](https://libssh2.org/libssh2_userauth_publickey_fromfile_ex.html)
   */
  template <class CompletionToken>
  auto async_public_key_auth(std::string_view username, const std::filesystem::path& pubkey,
                             const std::filesystem::path& privkey, CompletionToken&& handler) {
    return boost::asio::async_compose<CompletionToken, void(const std::error_code&)>(
      detail::async_public_key_auth<socket_type>{socket_, session_.get(), username, pubkey, privkey}, handler, get_executor());
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
    ec = do_blocking_call(api::libssh2_userauth_password_ex,
                          username.data(),
                          static_cast<unsigned int>(username.size()),
                          password.data(),
                          static_cast<unsigned int>(password.size()),
                          nullptr);
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

  /** Authenticate a session with a username and password
   *
   * This function call always returns immediately.
   *
   * @param username The user to authenticate. The implementation will
   * keep a copy of this argument.
   *
   * @param password Password to use for authenticating user. The
   * implementation will keep a copy of this argument.
   *
   * @param handler The handler to be called when the operation
   * completes. The implementation takes ownership of the handler by
   * performing a decay-copy. The handler must be invocable with this
   * signature:
   * @code
   * void handler(
   *     const std::error_code& // Result of operation.
   * );
   * @endcode
   *
   * @note Regardless of whether the asynchronous operation completes
   * immediately or not, the handler will not be invoked from within
   * this function. Invocation of the handler will be performed in a
   * manner equivalent to using `net::post`.
   *
   * @see [libssh2_userauth_password_ex](https://libssh2.org/libssh2_userauth_password_ex.html)
   */
  template <class CompletionToken>
  auto async_password_auth(std::string_view username, std::string_view password,
                           CompletionToken&& handler) {
    return boost::asio::async_compose<CompletionToken, void(const std::error_code&)>(
      detail::async_password_auth<socket_type>{socket_, session_.get(), username, password}, handler, get_executor());
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
    api::libssh2_session_set_blocking(handle(), 1);
    remote_directory_entry entry{};
    LIBSSH2_CHANNEL* chan = api::libssh2_scp_recv2(handle(), path.c_str(), &entry.stat_);
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

  /** Terminate transport layer
   *
   * Requests graceful shutdown of the SSH session.
   *
   * @param reason Human readable reason for disconnection.
   *
   * @param ec Set to indicate what error occurred, if any.
   *
   * @see [libssh2_session_disconnect_ex](https://libssh2.org/libssh2_session_disconnect_ex.html)
   *
   */
  void disconnect(const std::string& reason, std::error_code& ec) {
    ec = do_blocking_call(api::libssh2_session_disconnect_ex, SSH_DISCONNECT_BY_APPLICATION, reason.c_str(), "");
  }

  /** Terminate transport layer
   *
   * Requests graceful shutdown of the SSH session.
   *
   * @param reason Human readable reason for disconnection.
   *
   * @throws std::system_error Thrown on failure.
   *
   * @see [libssh2_session_disconnect_ex](https://libssh2.org/libssh2_session_disconnect_ex.html)
   *
   */
  void disconnect(const std::string& reason) {
    std::error_code ec{};
    disconnect(reason.c_str(), ec);
    detail::throw_on_error(ec, "disconnect");
  }

private:
  template<typename Func, typename... Args>
  std::error_code do_blocking_call(Func&& func, Args&&... args) {
    api::libssh2_session_set_blocking(handle(), 1);
    return {func(handle(), std::forward<Args>(args)...), libssh2_error_category()};
  }

  socket_type socket_;
  std::unique_ptr<LIBSSH2_SESSION, decltype(&detail::libssh2_api::libssh2_session_free)> session_;
};

} // namespace async_ssh

#endif // ASYNC_SSH_SESSION_HPP
