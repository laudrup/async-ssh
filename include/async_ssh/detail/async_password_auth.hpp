#ifndef ASYNC_SSH_DETAIL_ASYNC_PASSWORD_AUTH_HPP
#define ASYNC_SSH_DETAIL_ASYNC_PASSWORD_AUTH_HPP

#include <async_ssh/detail/async_op.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

namespace async_ssh::detail {

namespace api = detail::libssh2_api;

struct do_password_auth {
  explicit do_password_auth(std::string_view username,
                            std::string_view password)
    : username_(username.data(), username.size())
    , password_(password.data(), password.size()) {
  }

  int operator()(LIBSSH2_SESSION* session) {
        return api::libssh2_userauth_password_ex(session,
                                                 username_.c_str(),
                                                 static_cast<unsigned int>(username_.size()),
                                                 password_.c_str(),
                                                 static_cast<unsigned int>(password_.size()),
                                                 nullptr);
  }

private:
  std::string username_;
  std::string password_;
};

template <typename Socket>
struct async_password_auth : async_op<Socket, do_password_auth> {
  async_password_auth(Socket& socket, LIBSSH2_SESSION* session,
                      std::string_view username, std::string_view password)
    : async_op<Socket, do_password_auth>(socket, session, do_password_auth(username, password)) {
  }
};

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ASYNC_PASSWORD_AUTH_HPP
