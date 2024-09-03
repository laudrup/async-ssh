#ifndef ASYNC_SSH_TEST_SOCKET_MOCK_HPP
#define ASYNC_SSH_TEST_SOCKET_MOCK_HPP

#include <trompeloeil.hpp>

#include <libssh2.h>

namespace async_ssh::test {

using named_expectation = std::unique_ptr<trompeloeil::expectation>;

class socket_mock {
public:
  template <class Arg>
  socket_mock(Arg&)
    : socket_handle_calls(NAMED_ALLOW_CALL(*this, native_handle()).RETURN(socket_handle)) {
  }
  MAKE_MOCK0(native_handle, libssh2_socket_t());

  libssh2_socket_t socket_handle = static_cast<libssh2_socket_t>(0x2ULL);
  named_expectation socket_handle_calls;
};

} // namespace async_ssh::test

#endif // ASYNC_SSH_TEST_SOCKET_MOCK_HPP
