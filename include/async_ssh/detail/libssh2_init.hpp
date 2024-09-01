#ifndef ASYNC_SSH_DETAIL_LIBSSH2_INIT_HPP
#define ASYNC_SSH_DETAIL_LIBSSH2_INIT_HPP

namespace async_ssh::detail {

class libssh2_init {
public:
  libssh2_init() noexcept;
  ~libssh2_init();
  libssh2_init(const libssh2_init&) = delete;
  libssh2_init& operator=(const libssh2_init&) = delete;
  libssh2_init(libssh2_init&&) = delete;
  libssh2_init operator=(libssh2_init&&) = delete;
};

static inline const libssh2_init libssh2_init_instance;

}  // namespace async_ssh::detail

#include <async_ssh/detail/impl/libssh2_init.ipp>

#endif // ASYNC_SSH_DETAIL_LIBSSH2_INIT_HPP
