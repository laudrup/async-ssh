#ifndef ASYNC_SSH_DETAIL_ASYNC_DISCONNECT_HPP
#define ASYNC_SSH_DETAIL_ASYNC_DISCONNECT_HPP

#include <async_ssh/detail/async_op.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

namespace async_ssh::detail {

namespace api = detail::libssh2_api;

template <typename Socket>
struct do_disconnect {
  do_disconnect(Socket& socket, std::string reason)
    : socket_(socket)
    , reason_(std::move(reason)) {
  }

  int operator()(LIBSSH2_SESSION* session) {
    return api::libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, reason_.c_str(), "");
  }

private:
  Socket& socket_;
  std::string reason_;
};

template <typename Socket>
struct async_disconnect : async_op<Socket, do_disconnect<Socket>> {
  async_disconnect(Socket& socket, LIBSSH2_SESSION* session, const std::string& reason)
    : async_op<Socket, do_disconnect<Socket>>(socket, session, do_disconnect(socket, reason)) {
  }
};

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ASYNC_DISCONNECT_HPP
