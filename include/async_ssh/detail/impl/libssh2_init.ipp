#ifndef ASYNC_SSH_DETAIL_IMPL_LIBSSH2_INIT_IPP
#define ASYNC_SSH_DETAIL_IMPL_LIBSSH2_INIT_IPP

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

namespace async_ssh::detail {

libssh2_init::libssh2_init() noexcept {
  libssh2_api::libssh2_init(0);
}

libssh2_init::~libssh2_init() {
  libssh2_api::libssh2_exit();
}

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_IMPL_LIBSSH2_INIT_IPP
