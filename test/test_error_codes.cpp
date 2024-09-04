#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libssh2.h>

TEST_CASE("error codes") {
  auto [code, str] = GENERATE(table<int, std::string>({
    {LIBSSH2_ERROR_NONE, "None."},
    {LIBSSH2_ERROR_SOCKET_NONE, "The socket is invalid."},
    {LIBSSH2_ERROR_BANNER_RECV, "Unable to receive banner from remote host."},
    {LIBSSH2_ERROR_BANNER_SEND, "Unable to send banner to remote host."},
    {LIBSSH2_ERROR_INVALID_MAC, "Invalid MAC"},
    {LIBSSH2_ERROR_KEX_FAILURE, "Encryption key exchange with the remote host failed."},
    {LIBSSH2_ERROR_ALLOC, "An internal memory allocation call failed."},
    {LIBSSH2_ERROR_SOCKET_SEND, "Unable to send data on socket."},
    {LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE, "Key exchange failure."},
    {LIBSSH2_ERROR_TIMEOUT, "Timeout."},
    {LIBSSH2_ERROR_HOSTKEY_INIT, "Hostkey initialization error."},
    {LIBSSH2_ERROR_HOSTKEY_SIGN, "Hostkey signing error."},
    {LIBSSH2_ERROR_DECRYPT, "Decryption error."},
    {LIBSSH2_ERROR_SOCKET_DISCONNECT, "The socket was disconnected."},
    {LIBSSH2_ERROR_PROTO, "An invalid SSH protocol response was received on the socket"},
    {LIBSSH2_ERROR_PASSWORD_EXPIRED, "Password expired."},
    {LIBSSH2_ERROR_FILE, "An issue opening, reading or parsing the disk file."},
    {LIBSSH2_ERROR_METHOD_NONE, "No method has been set."},
    {LIBSSH2_ERROR_AUTHENTICATION_FAILED, "Invalid username/password or public/private key."},
    {LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED, "Invalid username/password or public/private key."},
    {LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED, "The username/public key combination was invalid."},
    {LIBSSH2_ERROR_CHANNEL_OUTOFORDER, "Channel out of order."},
    {LIBSSH2_ERROR_CHANNEL_FAILURE, "Channel failure"},
    {LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED, "Channel request denied."},
    {LIBSSH2_ERROR_CHANNEL_UNKNOWN, "Channel unknown."},
    {LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED, "Channel window exceeded."},
    {LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED, "Channel packet exceeded."},
    {LIBSSH2_ERROR_CHANNEL_CLOSED, "The channel has been closed."},
    {LIBSSH2_ERROR_CHANNEL_EOF_SENT, "The channel has been requested to be closed."},
    {LIBSSH2_ERROR_SCP_PROTOCOL, "SCP protocol error."},
    {LIBSSH2_ERROR_ZLIB, "ZLib error"},
    {LIBSSH2_ERROR_SOCKET_TIMEOUT, "Socket timeout"},
    {LIBSSH2_ERROR_SFTP_PROTOCOL, "An invalid SFTP protocol response was received on the socket, or an SFTP operation caused an errorcode to be returned by the server."},
    {LIBSSH2_ERROR_REQUEST_DENIED, "The remote server refused the request."},
    {LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "The requested method is not supported."},
    {LIBSSH2_ERROR_INVAL, "The requested method type was invalid."},
    {LIBSSH2_ERROR_INVALID_POLL_TYPE, "Invalid poll type."},
    {LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Public key protocol error."},
    {LIBSSH2_ERROR_EAGAIN, "Marked for non-blocking I/O but the call would block."},
    {LIBSSH2_ERROR_BUFFER_TOO_SMALL, "Buffer too small."},
    {LIBSSH2_ERROR_BAD_USE, "Invalid address of algs."},
    {LIBSSH2_ERROR_COMPRESS, "Compression error."},
    {LIBSSH2_ERROR_OUT_OF_BOUNDARY, "Out of boundary."},
    {LIBSSH2_ERROR_AGENT_PROTOCOL, "Agent protocol error."},
    {LIBSSH2_ERROR_SOCKET_RECV, "Socket receive error."},
    {LIBSSH2_ERROR_ENCRYPT, "Encryption error."},
    {LIBSSH2_ERROR_BAD_SOCKET, "Bad socket."},
    {LIBSSH2_ERROR_KNOWN_HOSTS, "Known hosts error."},
    {LIBSSH2_ERROR_CHANNEL_WINDOW_FULL, "Channel window full."},
    {LIBSSH2_ERROR_KEYFILE_AUTH_FAILED, "Keyfile authentication error."},
    {LIBSSH2_ERROR_RANDGEN, "Random number generation error."},
    {LIBSSH2_ERROR_BANNER_NONE, "Unable to receive banner from remote host."}
  }));

  CHECK(async_ssh::make_error_code(code).message() == str);
}
