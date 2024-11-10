#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"
#include "socket_mock.hpp"
#include "catch2_matchers.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libssh2.h>
#include <trompeloeil.hpp>

#include <boost/asio/io_context.hpp>

#include <new>
#include <system_error>

using async_ssh::test::session_fixture;
using mock_session = async_ssh::basic_session<async_ssh::test::socket_mock>;

TEST_CASE("Session init") {
  boost::asio::io_context ctx;
  LIBSSH2_SESSION* ptr = reinterpret_cast<LIBSSH2_SESSION*>(0xdecafbadULL);

  SECTION("No errors") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
      .RETURN(ptr);

    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_free(ptr))
      .RETURN(0);

    CHECK_NOTHROW(mock_session(ctx));
  }

  SECTION("Allocation failure") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
      .RETURN(nullptr);
  CHECK_THROWS_AS(mock_session(ctx), std::bad_alloc);
  }

  SECTION("Move") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_init_ex(nullptr, nullptr, nullptr, nullptr))
      .RETURN(ptr)
      .TIMES(2);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_free(ptr))
      .RETURN(0)
      .TIMES(2);

    mock_session session(ctx);
    auto moved_object(std::move(session));

    mock_session another_session(ctx);
    another_session = std::move(moved_object);
  }
}

TEST_CASE_METHOD(session_fixture, "Session hostkey hash") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  SECTION("Hash key length") {
    const char* hash = "dededededededededededededededede";
    auto [hash_type, length] = GENERATE(table<async_ssh::hostkey_hash_type, size_t>({
          { async_ssh::hostkey_hash_type::md5, 16 },
          { async_ssh::hostkey_hash_type::sha1, 20 },
          { async_ssh::hostkey_hash_type::sha256, 32 }
    }));
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_hostkey_hash(libssh2_session_ptr, static_cast<int>(hash_type)))
      .RETURN(hash);
    std::error_code ec = std::make_error_code(std::io_errc::stream);
    const auto fingerprint = session.hostkey_hash(hash_type, ec);
    CHECK(fingerprint.size() == length);
    CHECK_FALSE(ec);
  }

  SECTION("Hash key failure") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_hostkey_hash(libssh2_session_ptr, static_cast<int>(async_ssh::hostkey_hash_type::sha1)))
      .RETURN(nullptr)
      .TIMES(2);
    std::error_code ec{};
    const auto fingerprint = session.hostkey_hash(async_ssh::hostkey_hash_type::sha1, ec);
    CHECK(ec == make_error_code(async_ssh::errors::hostkey_unavailable));
    CHECK(fingerprint.empty());
    CHECK_THROWS_MATCHES(session.hostkey_hash(async_ssh::hostkey_hash_type::sha1),
                         std::system_error,
                         error_code_matches(make_error_code(async_ssh::errors::hostkey_unavailable)));
  }
}

TEST_CASE_METHOD(session_fixture, "Session disconnect") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;
  std::string reason{"Time to say goodbye"};

  SECTION("Blocking") {
    SECTION("No error") {
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 1))
        .TIMES(2);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_disconnect_ex(libssh2_session_ptr, SSH_DISCONNECT_BY_APPLICATION,
                                                 trompeloeil::_, trompeloeil::_))
        .WITH(std::string(_3) == reason)
        .RETURN(0)
        .TIMES(2);

      std::error_code ec;
      session.disconnect(reason, ec);
      CHECK_FALSE(ec);
      CHECK_NOTHROW(session.disconnect(reason));
    }

    SECTION("Disconnect errors") {
      auto rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 1))
        .TIMES(2);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_disconnect_ex(libssh2_session_ptr, SSH_DISCONNECT_BY_APPLICATION,
                                                 trompeloeil::_, trompeloeil::_))
        .WITH(std::string(_3) == reason)
        .RETURN(rc)
        .TIMES(2);

      std::error_code ec;
      session.disconnect(reason, ec);
      CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
      CHECK_THROWS_MATCHES(session.disconnect(reason),
                           std::system_error,
                           error_code_matches(make_error_code(static_cast<async_ssh::libssh2_errors>(rc))));
    }
  }

  SECTION("Async") {
    SECTION("No error") {
      trompeloeil::sequence seq;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_disconnect_ex(libssh2_session_ptr, SSH_DISCONNECT_BY_APPLICATION,
                                                 trompeloeil::_, trompeloeil::_))
        .WITH(std::string(_3) == reason)
        .RETURN(LIBSSH2_ERROR_EAGAIN)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_disconnect_ex(libssh2_session_ptr, SSH_DISCONNECT_BY_APPLICATION,
                                                 trompeloeil::_, trompeloeil::_))
        .WITH(std::string(_3) == reason)
        .RETURN(LIBSSH2_ERROR_NONE)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_block_directions(libssh2_session_ptr))
        .RETURN(LIBSSH2_SESSION_BLOCK_INBOUND);
      REQUIRE_CALL(session.socket(),
                   async_wait_completed(boost::asio::ip::tcp::socket::wait_read))
        .RETURN(std::error_code{});;

      session.async_disconnect(reason, [](const std::error_code& ec) {
        CHECK_FALSE(ec);
      });
      io_context.run();
    }

    SECTION("Disconnect errors") {
      auto rc = LIBSSH2_ERROR_BAD_USE;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_disconnect_ex(libssh2_session_ptr, SSH_DISCONNECT_BY_APPLICATION,
                                                 trompeloeil::_, trompeloeil::_))
        .WITH(std::string(_3) == reason)
        .RETURN(rc);
      session.async_disconnect(reason, [rc](const std::error_code& ec) {
        CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
      });
      io_context.run();
    }
  }
}
