#ifndef ASYNC_SSH_DETAIL_ERROR_HPP
#define ASYNC_SSH_DETAIL_ERROR_HPP

#include <system_error>

namespace async_ssh::detail {

inline void throw_on_error(const std::error_code& ec) {
  if (ec) {
    throw std::system_error{ec};
  }
}

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ERROR_HPP
