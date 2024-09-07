#ifndef ASYNC_SSH_ERROR_HPP
#define ASYNC_SSH_ERROR_HPP

#include <libssh2.h>

#include <system_error>

namespace async_ssh {

enum class libssh2_errors {
  none = LIBSSH2_ERROR_NONE,
  socket_none = LIBSSH2_ERROR_SOCKET_NONE,
  banner_recv = LIBSSH2_ERROR_BANNER_RECV,
  banner_send = LIBSSH2_ERROR_BANNER_SEND,
  invalid_mac = LIBSSH2_ERROR_INVALID_MAC,
  kex_failure = LIBSSH2_ERROR_KEX_FAILURE,
  alloc = LIBSSH2_ERROR_ALLOC,
  socket_send = LIBSSH2_ERROR_SOCKET_SEND,
  key_exchange_failure = LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE,
  timeout = LIBSSH2_ERROR_TIMEOUT,
  hostkey_init = LIBSSH2_ERROR_HOSTKEY_INIT,
  hostkey_sign = LIBSSH2_ERROR_HOSTKEY_SIGN,
  decrypt = LIBSSH2_ERROR_DECRYPT,
  socket_disconnect = LIBSSH2_ERROR_SOCKET_DISCONNECT,
  proto = LIBSSH2_ERROR_PROTO,
  password_expired = LIBSSH2_ERROR_PASSWORD_EXPIRED,
  file = LIBSSH2_ERROR_FILE,
  method_none = LIBSSH2_ERROR_METHOD_NONE,
  authentication_failed = LIBSSH2_ERROR_AUTHENTICATION_FAILED,
  publickey_unverified = LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
  channel_outoforder = LIBSSH2_ERROR_CHANNEL_OUTOFORDER,
  channel_failure = LIBSSH2_ERROR_CHANNEL_FAILURE,
  channel_request_denied = LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED,
  channel_unknown = LIBSSH2_ERROR_CHANNEL_UNKNOWN,
  channel_window_exceeded = LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED,
  channel_packet_exceeded = LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED,
  channel_closed = LIBSSH2_ERROR_CHANNEL_CLOSED,
  channel_eof_sent = LIBSSH2_ERROR_CHANNEL_EOF_SENT,
  scp_protocol = LIBSSH2_ERROR_SCP_PROTOCOL,
  zlib = LIBSSH2_ERROR_ZLIB,
  socket_timeout = LIBSSH2_ERROR_SOCKET_TIMEOUT,
  sftp_protocol = LIBSSH2_ERROR_SFTP_PROTOCOL,
  request_denied = LIBSSH2_ERROR_REQUEST_DENIED,
  method_not_supported = LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
  inval = LIBSSH2_ERROR_INVAL,
  invalid_poll_type = LIBSSH2_ERROR_INVALID_POLL_TYPE,
  publickey_protocol = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
  eagain = LIBSSH2_ERROR_EAGAIN,
  buffer_too_small = LIBSSH2_ERROR_BUFFER_TOO_SMALL,
  bad_use = LIBSSH2_ERROR_BAD_USE,
  compress = LIBSSH2_ERROR_COMPRESS,
  out_of_boundary = LIBSSH2_ERROR_OUT_OF_BOUNDARY,
  agent_protocol = LIBSSH2_ERROR_AGENT_PROTOCOL,
  socket_recv = LIBSSH2_ERROR_SOCKET_RECV,
  encrypt = LIBSSH2_ERROR_ENCRYPT,
  bad_socket = LIBSSH2_ERROR_BAD_SOCKET,
  known_hosts = LIBSSH2_ERROR_KNOWN_HOSTS,
  channel_window_full = LIBSSH2_ERROR_CHANNEL_WINDOW_FULL,
  keyfile_auth_failed = LIBSSH2_ERROR_KEYFILE_AUTH_FAILED,
  randgen = LIBSSH2_ERROR_RANDGEN
};

const std::error_category& libssh2_error_category();

/// Errors used by this library
enum class errors {
  /// No error
  none = 0,

  /// The hostkey is unavailable
  hostkey_unavailable
};

const std::error_category& error_category();

}  // namespace async_ssh

namespace std {

template<>
struct is_error_code_enum<async_ssh::libssh2_errors> {
  static const bool value = true;
};

template<>
struct is_error_code_enum<async_ssh::errors> {
  static const bool value = true;
};

} // namespace std

namespace async_ssh {

inline std::error_code make_error_code(libssh2_errors e) {
  return {static_cast<int>(e), libssh2_error_category()};
}

inline std::error_code make_error_code(errors e) {
  return {static_cast<int>(e), error_category()};
}

} // namespace async_ssh

#include <async_ssh/impl/error.ipp>

#endif // ASYNC_SSH_ERROR_HPP
