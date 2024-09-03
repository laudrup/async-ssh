#ifndef ASYNC_SSH_TEST_SESSION_FIXTURE_HPP
#define ASYNC_SSH_TEST_SESSION_FIXTURE_HPP

#include "libssh2_api_mock.hpp"
#include "socket_mock.hpp"

#include <async_ssh.hpp>

#include <trompeloeil.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <vector>

namespace async_ssh::test {

// From: https://stackoverflow.com/a/72972009
template <typename T, typename... Args>
inline std::vector<T> make_vector(Args&&... args) {
  std::vector<T> container;
  container.reserve(sizeof...(Args));
  ((container.emplace_back(std::forward<Args>(args))), ...);
  return container;
}

using named_expectation = std::unique_ptr<trompeloeil::expectation>;

class session_fixture {
public:
  session_fixture()
    : expectations_{
        make_vector<named_expectation>(NAMED_REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                                                          libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
                                       .LR_RETURN(libssh2_session_ptr),
                                       NAMED_REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                                                          libssh2_session_free(libssh2_session_ptr))
                                       .RETURN(0),
                                       NAMED_REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                                                          libssh2_session_disconnect_ex(libssh2_session_ptr, 11, "Goodbye", ""))
                                       .RETURN(0))
      }
    , session(io_context) {
  }

protected:
  LIBSSH2_SESSION* libssh2_session_ptr = reinterpret_cast<LIBSSH2_SESSION*>(0x1ULL);

private:
  std::vector<std::unique_ptr<trompeloeil::expectation>> expectations_;

protected:
  boost::asio::io_context io_context;
  async_ssh::session<socket_mock> session;
};

} // namespace async_ssh::test

#endif // ASYNC_SSH_TEST_SESSION_FIXTURE_HPP
