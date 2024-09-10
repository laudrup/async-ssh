#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"
#include "catch2_matchers.hpp"
#include "catch2_string_makers.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libssh2.h>
#include <trompeloeil.hpp>

#include <filesystem>
#include <system_error>

using async_ssh::test::session_fixture;

TEST_CASE_METHOD(session_fixture, "scp") {
  std::filesystem::path path{"/somewhere/something"};
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  SECTION("scp error") {
    auto rc = LIBSSH2_ERROR_SCP_PROTOCOL;
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_scp_recv2(libssh2_session_ptr,
                                   trompeloeil::eq<const char*>(path.string()),
                                   trompeloeil::_))
      .RETURN(nullptr)
      .TIMES(2);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_last_errno(libssh2_session_ptr))
      .RETURN(rc)
      .TIMES(2);

    std::error_code ec;
    auto [channel, entry] = session.scp_recv(path, ec);
    CHECK(ec == make_error_code(static_cast<async_ssh::libssh2_errors>(rc)));
    CHECK_THROWS_MATCHES(session.scp_recv(path),
                         std::system_error,
                         error_code_matches(make_error_code(static_cast<async_ssh::libssh2_errors>(rc))));
  }
  SECTION("File types") {
    using std::filesystem::perms;
    LIBSSH2_CHANNEL* ptr = reinterpret_cast<LIBSSH2_CHANNEL*>(0xdecafbadULL);

    auto [file_type, mode] = GENERATE(table<std::filesystem::file_type, int>({
          { std::filesystem::file_type::regular, 0100666 },
          { std::filesystem::file_type::directory, 040666 },
          { std::filesystem::file_type::symlink, 0120666 },
          { std::filesystem::file_type::block, 060666 },
          { std::filesystem::file_type::character, 020666 },
          { std::filesystem::file_type::fifo, 010666 },
          { std::filesystem::file_type::socket, 0140666 }
    }));

    auto st_mode = static_cast<unsigned short>(mode);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_scp_recv2(libssh2_session_ptr,
                                   trompeloeil::eq<const char*>(path.string()),
                                   trompeloeil::_))
      .LR_SIDE_EFFECT(_3->st_mode = st_mode)
      .RETURN(ptr);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_channel_free(ptr))
      .RETURN(0);

    const auto [channel, entry] = session.scp_recv(path);
    CHECK(entry.status().type() == file_type);
    CHECK(entry.status().permissions() ==
          (perms::owner_read | perms::owner_write |
           perms::group_read | perms::group_write |
           perms::others_read | perms::others_write));
  }
}
