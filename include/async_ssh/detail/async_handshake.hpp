#ifndef ASYNC_SSH_DETAIL_ASYNC_HANDSHAKE_HPP
#define ASYNC_SSH_DETAIL_ASYNC_HANDSHAKE_HPP

#include <async_ssh/detail/async_op.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

namespace async_ssh::detail {

namespace api = detail::libssh2_api;

template <typename Socket>
struct do_handshake {
  explicit do_handshake(Socket& socket)
    : socket_(socket) {
  }

  int operator()(LIBSSH2_SESSION* session) {
    return api::libssh2_session_handshake(session, socket_.native_handle());
  }

private:
  Socket& socket_;
};

template <typename Socket>
struct async_handshake : async_op<Socket, do_handshake<Socket>> {
  async_handshake(Socket& socket, LIBSSH2_SESSION* session)
    : async_op<Socket, do_handshake<Socket>>(socket, session, do_handshake(socket)) {
  }
};

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ASYNC_HANDSHAKE_HPP
