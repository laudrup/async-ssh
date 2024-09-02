#include "libssh2_api_mock.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>

#include <trompeloeil.hpp>

#include <boost/asio.hpp>

class socket_mock {
public:
  template <class Arg>
  socket_mock(Arg&) {
  }
  MAKE_MOCK0(native_handle, libssh2_socket_t());
};

TEST_CASE("scp") {
  const auto libssh2_session_ptr = reinterpret_cast<LIBSSH2_SESSION*>(0xdecafbad);
  REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance, libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
    .LR_RETURN(libssh2_session_ptr);
  REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance, libssh2_session_free(libssh2_session_ptr))
    .RETURN(0);
  REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance, libssh2_session_disconnect_ex(libssh2_session_ptr, 11, "Goodbye", ""))
    .RETURN(0);

  boost::asio::io_context ctx;
  async_ssh::session<socket_mock> sess(ctx);
}
