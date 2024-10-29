#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"
#include "catch2_matchers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libssh2.h>
#include <trompeloeil.hpp>

#include <system_error>

using async_ssh::test::session_fixture;

TEST_CASE_METHOD(session_fixture, "Session handshake") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  SECTION("No errors") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_set_blocking(libssh2_session_ptr, 1))
      .TIMES(2);
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
                 libssh2_session_set_blocking(libssh2_session_ptr, 1))
      .TIMES(2);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
      .RETURN(rc)
      .TIMES(2);

    std::error_code ec;
    session.handshake(ec);
    CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
    CHECK_THROWS_MATCHES(session.handshake(),
                         std::system_error,
                         error_code_matches(make_error_code(static_cast<async_ssh::libssh2_errors>(rc))));
  }

  SECTION("Async handshake") {
    std::error_code error{};

    SECTION("No errors") {
      trompeloeil::sequence seq;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
        .RETURN(LIBSSH2_ERROR_EAGAIN)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
        .RETURN(LIBSSH2_ERROR_NONE)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_block_directions(libssh2_session_ptr))
        .RETURN(LIBSSH2_SESSION_BLOCK_INBOUND);
      REQUIRE_CALL(session.socket(),
                   async_wait_completed(boost::asio::ip::tcp::socket::wait_read))
        .RETURN(std::error_code{});

      error = make_error_code(std::errc::connection_aborted);
      session.async_handshake([&error](const std::error_code& ec) {
        error = ec;
      });
      CHECK(io_context.run() == 1);
      CHECK_FALSE(error);
    }

    SECTION("Socket failure") {
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
        .RETURN(LIBSSH2_ERROR_EAGAIN);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_block_directions(libssh2_session_ptr))
        .RETURN(LIBSSH2_SESSION_BLOCK_INBOUND);
      REQUIRE_CALL(session.socket(),
                   async_wait_completed(boost::asio::ip::tcp::socket::wait_read))
        .RETURN(std::make_error_code(std::errc::connection_aborted));

      session.async_handshake([&error](const std::error_code& ec) {
        error = ec;
      });
      CHECK(io_context.run() == 1);
      CHECK(error == make_error_code(std::errc::connection_aborted));
    }

    SECTION("Handshake function failure") {
      trompeloeil::sequence seq;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
        .RETURN(LIBSSH2_ERROR_EAGAIN)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
        .RETURN(LIBSSH2_ERROR_SOCKET_DISCONNECT)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_block_directions(libssh2_session_ptr))
        .RETURN(LIBSSH2_SESSION_BLOCK_INBOUND);
      REQUIRE_CALL(session.socket(),
                   async_wait_completed(boost::asio::ip::tcp::socket::wait_read))
        .RETURN(std::error_code{});

      session.async_handshake([&error](const std::error_code& ec) {
        error = ec;
      });
      CHECK(io_context.run() == 1);
      CHECK(error == make_error_code(static_cast<async_ssh::libssh2_errors>(LIBSSH2_ERROR_SOCKET_DISCONNECT)));
    }
  }
}
