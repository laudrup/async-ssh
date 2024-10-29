#ifndef ASYNC_SSH_TEST_SOCKET_MOCK_HPP
#define ASYNC_SSH_TEST_SOCKET_MOCK_HPP

#include <trompeloeil.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

#include <system_error>

namespace async_ssh::test {

using named_expectation = std::unique_ptr<trompeloeil::expectation>;

class socket_mock {
public:
  using executor_type = typename std::remove_reference<boost::asio::io_context>::type::executor_type;

  static constexpr bool trompeloeil_movable_mock = true;

  template <class Arg>
  explicit socket_mock(Arg& ctx)
    : io_context(ctx)
    , socket_handle_calls(NAMED_ALLOW_CALL(*this, native_handle()).RETURN(socket_handle)) {
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
  executor_type get_executor() {
    return io_context.get_executor();
  }

  MAKE_MOCK0(native_handle, libssh2_socket_t());
  MAKE_MOCK1(async_wait_completed, std::error_code(boost::asio::ip::tcp::socket::wait_type));

  // Cannot currently mock template functions:
  // https://github.com/rollbear/trompeloeil/issues/110
  template <class WaitToken>
  void async_wait(boost::asio::ip::tcp::socket::wait_type w, WaitToken&& token) {
    auto e = get_executor();
    boost::asio::post(e, [this, w, tok = std::move(token)]() mutable {
      const auto rc = async_wait_completed(w);
      tok(rc);
    });
  }

  boost::asio::io_context& io_context;
  libssh2_socket_t socket_handle = static_cast<libssh2_socket_t>(0x2ULL);
  named_expectation socket_handle_calls;
};

} // namespace async_ssh::test

#endif // ASYNC_SSH_TEST_SOCKET_MOCK_HPP
