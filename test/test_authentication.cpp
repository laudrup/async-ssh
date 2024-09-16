#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"
#include "catch2_matchers.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libssh2.h>
#include <trompeloeil.hpp>

#include <system_error>

using async_ssh::test::session_fixture;
using trompeloeil::_;

TEST_CASE_METHOD(session_fixture, "Session public key authentication") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  std::string username{"freja"};
  std::filesystem::path pubkey{"id_rsa.pub"};
  std::filesystem::path privkey{"id_rsa"};

  SECTION("Blocking") {
    SECTION("No error") {
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 1))
        .TIMES(2);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                          _,
                                                          static_cast<unsigned int>(username.size()),
                                                          _,
                                                          _,
                                                          nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == pubkey.string())
        .WITH(std::string(_5) == privkey.string())
        .RETURN(0)
        .TIMES(2);

      std::error_code ec;
      session.public_key_auth(username, pubkey, privkey, ec);
      CHECK_FALSE(ec);
      CHECK_NOTHROW(session.public_key_auth(username, pubkey, privkey));
    }

    SECTION("Authentication errors") {
      auto rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 1))
        .TIMES(2);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                          _,
                                                          static_cast<unsigned int>(username.size()),
                                                          _,
                                                          _,
                                                          nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == pubkey.string())
        .WITH(std::string(_5) == privkey.string())
        .RETURN(rc)
        .TIMES(2);

      std::error_code ec;
      session.public_key_auth(username, pubkey, privkey, ec);
      CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
      CHECK_THROWS_MATCHES(session.public_key_auth(username, pubkey, privkey),
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
                   libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                          _,
                                                          static_cast<unsigned int>(username.size()),
                                                          _,
                                                          _,
                                                          nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == pubkey.string())
        .WITH(std::string(_5) == privkey.string())
        .RETURN(LIBSSH2_ERROR_EAGAIN)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                          _,
                                                          static_cast<unsigned int>(username.size()),
                                                          _,
                                                          _,
                                                          nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == pubkey.string())
        .WITH(std::string(_5) == privkey.string())
        .RETURN(LIBSSH2_ERROR_NONE)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_block_directions(libssh2_session_ptr))
        .RETURN(LIBSSH2_SESSION_BLOCK_INBOUND);
      REQUIRE_CALL(session.socket(),
                   async_wait_completed(boost::asio::ip::tcp::socket::wait_read))
        .RETURN(std::error_code{});;

      session.async_public_key_auth(username, pubkey, privkey, [](const std::error_code& ec) {
        CHECK_FALSE(ec);
      });
      io_context.run();
    }

    SECTION("Authentication errors") {
      auto rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                          _,
                                                          static_cast<unsigned int>(username.size()),
                                                          _,
                                                          _,
                                                          nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == pubkey.string())
        .WITH(std::string(_5) == privkey.string())
        .RETURN(rc);

      session.async_public_key_auth(username, pubkey, privkey, [rc](const std::error_code& ec) {
        CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
      });
      io_context.run();
    }
  }
}

TEST_CASE_METHOD(session_fixture, "Session password authentication") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  std::string username{"freja"};
  std::string password{"hunter2"};

  SECTION("Blocking") {
    SECTION("No error") {
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 1))
        .TIMES(2);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_password_ex(libssh2_session_ptr,
                                                _,
                                                static_cast<unsigned int>(username.size()),
                                                _,
                                                static_cast<unsigned int>(password.size()),
                                                nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == password)
        .RETURN(0)
        .TIMES(2);

      std::error_code ec;
      session.password_auth(username, password, ec);
      CHECK_FALSE(ec);
      CHECK_NOTHROW(session.password_auth(username, password));
    }

    SECTION("Authentication errors") {
      auto rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 1))
        .TIMES(2);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_password_ex(libssh2_session_ptr,
                                                _,
                                                static_cast<unsigned int>(username.size()),
                                                _,
                                                static_cast<unsigned int>(password.size()),
                                                nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == password)
        .RETURN(rc)
        .TIMES(2);

      std::error_code ec;
      session.password_auth(username, password, ec);
      CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
      CHECK_THROWS_MATCHES(session.password_auth(username, password),
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
                   libssh2_userauth_password_ex(libssh2_session_ptr,
                                                _,
                                                static_cast<unsigned int>(username.size()),
                                                _,
                                                static_cast<unsigned int>(password.size()),
                                                nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == password)
        .RETURN(LIBSSH2_ERROR_EAGAIN)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_password_ex(libssh2_session_ptr,
                                                _,
                                                static_cast<unsigned int>(username.size()),
                                                _,
                                                static_cast<unsigned int>(password.size()),
                                                nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == password)
        .RETURN(LIBSSH2_ERROR_NONE)
        .IN_SEQUENCE(seq);
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_block_directions(libssh2_session_ptr))
        .RETURN(LIBSSH2_SESSION_BLOCK_INBOUND);
      REQUIRE_CALL(session.socket(),
                   async_wait_completed(boost::asio::ip::tcp::socket::wait_read))
        .RETURN(std::error_code{});;

      session.async_password_auth(username, password, [](const std::error_code& ec) {
        CHECK_FALSE(ec);
      });
      io_context.run();
    }

    SECTION("Authentication errors") {
      auto rc = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_session_set_blocking(libssh2_session_ptr, 0));
      REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                   libssh2_userauth_password_ex(libssh2_session_ptr,
                                                _,
                                                static_cast<unsigned int>(username.size()),
                                                _,
                                                static_cast<unsigned int>(password.size()),
                                                nullptr))
        .WITH(std::string(_2) == username)
        .WITH(std::string(_4) == password)
        .RETURN(rc);

      session.async_password_auth(username, password, [rc](const std::error_code& ec) {
        CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
      });
      io_context.run();
    }
  }
}
