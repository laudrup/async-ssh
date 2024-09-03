#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>

#include <trompeloeil.hpp>

TEST_CASE_METHOD(async_ssh::test::session_fixture, "session") {
  REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
               libssh2_session_handshake(libssh2_session_ptr, session.socket().socket_handle))
    .RETURN(0);
  session.handshake();
}
