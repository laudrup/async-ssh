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

TEST_CASE("Session init") {
  boost::asio::io_context ctx;
  SECTION("No errors") {
    LIBSSH2_SESSION* ptr = reinterpret_cast<LIBSSH2_SESSION*>(0xdecafbadULL);

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

TEST_CASE_METHOD(session_fixture, "Session handshake") {
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
    CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
    CHECK_THROWS_MATCHES(session.handshake(),
                         std::system_error,
                         error_code_matches(make_error_code(static_cast<async_ssh::libssh2_errors>(rc))));
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

TEST_CASE_METHOD(session_fixture, "Session public key authentication") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  std::string username{"freja"};
  std::filesystem::path pubkey{"id_rsa.pub"};
  std::filesystem::path privkey{"id_rsa"};

  SECTION("No error") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                        username.data(),
                                                        static_cast<unsigned int>(username.size()),
                                                        trompeloeil::eq<const char*>(pubkey.string()),
                                                        trompeloeil::eq<const char*>(privkey.string()),
                                                        nullptr))
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
                 libssh2_userauth_publickey_fromfile_ex(libssh2_session_ptr,
                                                        username.data(),
                                                        static_cast<unsigned int>(username.size()),
                                                        trompeloeil::eq<const char*>(pubkey.string()),
                                                        trompeloeil::eq<const char*>(privkey.string()),
                                                        nullptr))
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

TEST_CASE_METHOD(session_fixture, "Session password authentication") {
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  std::string username{"freja"};
  std::string password{"hunter2"};

  SECTION("No error") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_userauth_password_ex(libssh2_session_ptr,
                                              username.data(),
                                              static_cast<unsigned int>(username.size()),
                                              password.data(),
                                              static_cast<unsigned int>(password.size()),
                                              nullptr))
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
                 libssh2_userauth_password_ex(libssh2_session_ptr,
                                              username.data(),
                                              static_cast<unsigned int>(username.size()),
                                              password.data(),
                                              static_cast<unsigned int>(password.size()),
                                              nullptr))

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
