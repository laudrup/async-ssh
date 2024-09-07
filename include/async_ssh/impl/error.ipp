#ifndef ASYNC_SSH_IMPL_ERROR_IPP
#define ASYNC_SSH_IMPL_ERROR_IPP

#include <system_error>

namespace async_ssh {
namespace detail {

class libssh2_error_category : public std::error_category {
public:
  const char* name() const noexcept override {
    return "libssh2";
  }

  std::string message(int err) const override {
    // liibssh2 doesn't have a function for converting error codes to
    // strings so these string are generated from libssh2
    // documentation or made by this library.
    switch (static_cast<libssh2_errors>(err)) {
      case libssh2_errors::none:
        return "None.";
      case libssh2_errors::socket_none:
        return "The socket is invalid.";
      case libssh2_errors::banner_recv:
        return "Unable to receive banner from remote host.";
      case libssh2_errors::banner_send:
        return "Unable to send banner to remote host.";
      case libssh2_errors::invalid_mac:
        return "Invalid MAC";
      case libssh2_errors::kex_failure:
        return "Encryption key exchange with the remote host failed.";
      case libssh2_errors::alloc:
        return "An internal memory allocation call failed.";
      case libssh2_errors::socket_send:
        return "Unable to send data on socket.";
      case libssh2_errors::key_exchange_failure:
        return "Key exchange failure.";
      case libssh2_errors::timeout:
        return "Timeout.";
      case libssh2_errors::hostkey_init:
        return "Hostkey initialization error.";
      case libssh2_errors::hostkey_sign:
        return "Hostkey signing error.";
      case libssh2_errors::decrypt:
        return "Decryption error.";
      case libssh2_errors::socket_disconnect:
        return "The socket was disconnected.";
      case libssh2_errors::proto:
        return "An invalid SSH protocol response was received on the socket";
      case libssh2_errors::password_expired:
        return "Password expired.";
      case libssh2_errors::file:
        return "An issue opening, reading or parsing the disk file.";
      case libssh2_errors::method_none:
        return "No method has been set.";
      case libssh2_errors::authentication_failed:
        return "Invalid username/password or public/private key.";
      case libssh2_errors::publickey_unverified:
        return "The username/public key combination was invalid.";
      case libssh2_errors::channel_outoforder:
        return "Channel out of order.";
      case libssh2_errors::channel_failure:
        return "Channel failure";
      case libssh2_errors::channel_request_denied:
        return "Channel request denied.";
      case libssh2_errors::channel_unknown:
        return "Channel unknown.";
      case libssh2_errors::channel_window_exceeded:
        return "Channel window exceeded.";
      case libssh2_errors::channel_packet_exceeded:
        return "Channel packet exceeded.";
      case libssh2_errors::channel_closed:
        return "The channel has been closed.";
      case libssh2_errors::channel_eof_sent:
        return "The channel has been requested to be closed.";
      case libssh2_errors::scp_protocol:
        return "SCP protocol error.";
      case libssh2_errors::zlib:
        return "ZLib error";
      case libssh2_errors::socket_timeout:
        return "Socket timeout";
      case libssh2_errors::sftp_protocol:
        return "An invalid SFTP protocol response was received on the socket, or "
          "an SFTP operation caused an errorcode to be returned by the "
          "server.";
      case libssh2_errors::request_denied:
        return "The remote server refused the request.";
      case libssh2_errors::method_not_supported:
        return "The requested method is not supported.";
      case libssh2_errors::inval:
        return "The requested method type was invalid.";
      case libssh2_errors::invalid_poll_type:
        return "Invalid poll type.";
      case libssh2_errors::publickey_protocol:
        return "Public key protocol error.";
      case libssh2_errors::eagain:
        return "Marked for non-blocking I/O but the call would block.";
      case libssh2_errors::buffer_too_small:
        return "Buffer too small.";
      case libssh2_errors::bad_use:
        return "Invalid address of algs.";
      case libssh2_errors::compress:
        return "Compression error.";
      case libssh2_errors::out_of_boundary:
        return "Out of boundary.";
      case libssh2_errors::agent_protocol:
        return "Agent protocol error.";
      case libssh2_errors::socket_recv:
        return "Socket receive error.";
      case libssh2_errors::encrypt:
        return "Encryption error.";
      case libssh2_errors::bad_socket:
        return "Bad socket.";
      case libssh2_errors::known_hosts:
        return "Known hosts error.";
      case libssh2_errors::channel_window_full:
        return "Channel window full.";
      case libssh2_errors::keyfile_auth_failed:
        return "Keyfile authentication error.";
      case libssh2_errors::randgen:
        return "Random number generation error.";
    }
    return "Unknown (" + std::to_string(err) + ")";
  }
};

class error_category : public std::error_category {
public:
  const char* name() const noexcept override {
    return "async-ssh";
  }

  std::string message(int err) const override {
    switch (static_cast<errors>(err)) {
      case errors::none:
        return "No error.";
      case errors::hostkey_unavailable:
        return "Hostkey unavailable.";
    }
    return "async-ssh error";
  }
};

} // namespace detail

inline const std::error_category& libssh2_error_category() {
  static detail::libssh2_error_category instance;
  return instance;
}

inline const std::error_category& error_category() {
  static detail::error_category instance;
  return instance;
}

} // namespace async_ssh

#endif // ASYNC_SSH_IMPL_ERROR_IPP
