#ifndef ASYNC_SSH_TEST_SOCKET_MOCK_HPP
#define ASYNC_SSH_TEST_SOCKET_MOCK_HPP

#include <trompeloeil.hpp>

#include <libssh2.h>

namespace async_ssh::test {

using named_expectation = std::unique_ptr<trompeloeil::expectation>;

class socket_mock {
public:
  static constexpr bool trompeloeil_movable_mock = true;

  template <class Arg>
  explicit socket_mock(Arg&)
    : socket_handle_calls(NAMED_ALLOW_CALL(*this, native_handle()).RETURN(socket_handle)) {
  }
  socket_mock(const socket_mock&) = delete;
  socket_mock& operator=(const socket_mock&) = delete;
  socket_mock(socket_mock&&) noexcept = default;
  socket_mock& operator=(socket_mock&& other) noexcept {
    if(this == &other) {
      return *this;
    }
    socket_handle = std::exchange(other.socket_handle, libssh2_socket_t{});
    socket_handle_calls = std::move(other.socket_handle_calls);
    return *this;
  }

  MAKE_MOCK0(native_handle, libssh2_socket_t());

  libssh2_socket_t socket_handle = static_cast<libssh2_socket_t>(0x2ULL);
  named_expectation socket_handle_calls;
};

} // namespace async_ssh::test

#endif // ASYNC_SSH_TEST_SOCKET_MOCK_HPP
