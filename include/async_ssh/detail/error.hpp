#ifndef ASYNC_SSH_DETAIL_ERROR_HPP
#define ASYNC_SSH_DETAIL_ERROR_HPP

#include <string>
#include <system_error>

namespace async_ssh::detail {

inline void throw_on_error(const std::error_code& ec, const std::string& what) {
  if (ec) {
    throw std::system_error{ec, what};
  }
}

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ERROR_HPP
