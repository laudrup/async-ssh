#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"
#include "socket_mock.hpp"
#include "catch2_matchers.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <trompeloeil.hpp>

#include <boost/asio/io_context.hpp>

#include <new>
#include <system_error>

using async_ssh::test::session_fixture;

TEST_CASE("session init") {
  boost::asio::io_context ctx;
  SECTION("No errors") {
    LIBSSH2_SESSION* ptr = reinterpret_cast<LIBSSH2_SESSION*>(0xdecafbad);

    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
      .RETURN(ptr);

    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_free(ptr))
      .RETURN(0);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_disconnect_ex(ptr, 11, "Goodbye", ""))
      .RETURN(0);

    CHECK_NOTHROW(async_ssh::session<async_ssh::test::socket_mock>(ctx));
  }

  SECTION("Allocation failure") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
      .RETURN(nullptr);
    CHECK_THROWS_AS(async_ssh::session<async_ssh::test::socket_mock>(ctx), std::bad_alloc);
  }
}

TEST_CASE_METHOD(session_fixture, "session handshake") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  SECTION("No errors") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
      .RETURN(0)
      .TIMES(2);

    std::error_code ec;
    session.handshake(ec);
    session.handshake();
  }

  SECTION("Expected errors") {
    auto rc = GENERATE(LIBSSH2_ERROR_SOCKET_NONE,
                       LIBSSH2_ERROR_BANNER_SEND,
                       LIBSSH2_ERROR_KEX_FAILURE,
                       LIBSSH2_ERROR_SOCKET_SEND,
                       LIBSSH2_ERROR_SOCKET_DISCONNECT,
                       LIBSSH2_ERROR_PROTO,
                       LIBSSH2_ERROR_EAGAIN);

    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
      .RETURN(rc)
      .TIMES(2);

    std::error_code ec;
    session.handshake(ec);
    CHECK(ec == make_error_code(rc));
    CHECK_THROWS_MATCHES(session.handshake(),
                         std::system_error,
                         error_code_matches(make_error_code(rc)));
  }
}
