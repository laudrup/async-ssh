#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"
#include "catch2_matchers.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libssh2.h>
#include <trompeloeil.hpp>

#include <chrono>
#include <filesystem>
#include <system_error>

using async_ssh::test::session_fixture;

std::string format_perms(std::filesystem::perms p) {
    using std::filesystem::perms;
    std::string str;
    auto append = [&str, p](char op, perms perm) {
        str += (perms::none == (perm & p) ? '-' : op);
    };
    append('r', perms::owner_read);
    append('w', perms::owner_write);
    append('x', perms::owner_exec);
    append('r', perms::group_read);
    append('w', perms::group_write);
    append('x', perms::group_exec);
    append('r', perms::others_read);
    append('w', perms::others_write);
    append('x', perms::others_exec);
    return str;
}

TEST_CASE_METHOD(session_fixture, "scp") {
  std::filesystem::path path{"/somewhere/something"};
  using async_ssh::test::error_code_matches;
  using async_ssh::make_error_code;

  SECTION("scp error") {
    auto rc = LIBSSH2_ERROR_SCP_PROTOCOL;
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_set_blocking(libssh2_session_ptr, 1))
      .TIMES(2);
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
  SECTION("File metadata") {
    using std::filesystem::perms;
    LIBSSH2_CHANNEL* ptr = reinterpret_cast<LIBSSH2_CHANNEL*>(0xdecafbadULL);
    const std::time_t mtime = 1498001148;
    const std::time_t atime = 1728822518;
    const std::size_t size = 18374625329;

    auto [str, mode] = GENERATE(table<std::string, unsigned short>({
          { "rw-rw-rw-", 0666 },
          { "---------", 0000 },
          { "---r-----", 0040 },
          { "r-----r--", 0404 },
          { "rw-r--r--", 0644 },
          { "rwxr-xr-x", 0755 }
    }));

    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_session_set_blocking(libssh2_session_ptr, 1));
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_scp_recv2(libssh2_session_ptr,
                                   trompeloeil::eq<const char*>(path.string()),
                                   trompeloeil::_))
      .LR_SIDE_EFFECT(_3->st_mode = mode)
      .LR_SIDE_EFFECT(_3->st_mtime = mtime)
      .LR_SIDE_EFFECT(_3->st_atime = atime)
      .LR_SIDE_EFFECT(_3->st_size = size)
      .RETURN(ptr);
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_channel_free(ptr))
      .RETURN(0);

    const auto [channel, entry] = session.scp_recv(path);
    CHECK(format_perms(entry.permissions()) == str);
    CHECK(std::chrono::system_clock::to_time_t(entry.last_write_time()) == mtime);
    CHECK(std::chrono::system_clock::to_time_t(entry.last_access_time()) == atime);
    CHECK(entry.size() == size);
  }
}
