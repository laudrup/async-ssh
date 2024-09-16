#ifndef ASYNC_SSH_DETAIL_ASYNC_PUBLIC_KEY_AUTH_HPP
#define ASYNC_SSH_DETAIL_ASYNC_PUBLIC_KEY_AUTH_HPP

#include <async_ssh/detail/async_op.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

#include <filesystem>
#include <utility>

namespace async_ssh::detail {

namespace api = detail::libssh2_api;

struct do_public_key_auth {
  explicit do_public_key_auth(std::string_view username,
                              std::filesystem::path pubkey,
                              std::filesystem::path privkey)
    : username_(username.data(), username.size())
    , pubkey_(std::move(pubkey))
    , privkey_(std::move(privkey)) {
  }

  int operator()(LIBSSH2_SESSION* session) {
    return api::libssh2_userauth_publickey_fromfile_ex(session,
                                                       username_.c_str(),
                                                       static_cast<unsigned int>(username_.size()),
                                                       pubkey_.string().c_str(),
                                                       privkey_.string().c_str(),
                                                       nullptr);
  }

private:
  std::string username_;
  std::filesystem::path pubkey_;
  std::filesystem::path privkey_;
};

template <typename Socket>
struct async_public_key_auth : async_op<Socket, do_public_key_auth> {
  async_public_key_auth(Socket& socket, LIBSSH2_SESSION* session,
                        std::string_view username, const std::filesystem::path& pubkey,
                        const std::filesystem::path& privkey)
    : async_op<Socket, do_public_key_auth>(socket, session, do_public_key_auth(username, pubkey, privkey)) {
  }
};

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ASYNC_PUBLIC_KEY_AUTH_HPP
