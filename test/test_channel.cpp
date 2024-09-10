#include "session_fixture.hpp"
#include "libssh2_api_mock.hpp"

#include <async_ssh.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libssh2.h>

#include <trompeloeil.hpp>

#include <algorithm>
#include <system_error>

using async_ssh::test::session_fixture;

TEST_CASE_METHOD(session_fixture, "channel") {
  std::filesystem::path path{"/somewhere/something"};
  LIBSSH2_CHANNEL* ptr = reinterpret_cast<LIBSSH2_CHANNEL*>(0xdecafbadULL);
  REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
               libssh2_scp_recv2(libssh2_session_ptr,
                                 trompeloeil::eq<const char*>(path.string()),
                                 trompeloeil::_))
    .RETURN(ptr);
  REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
               libssh2_channel_free(ptr))
    .RETURN(0);

  SECTION("Empty read") {
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_channel_read_ex(ptr, 0, trompeloeil::_, 1024UL))
      .RETURN(0);


    std::error_code ec;
    auto [channel, entry] = session.scp_recv(path, ec);
    std::array<char, 1024> mem{};
    channel.read_some(boost::asio::buffer(mem));
  }

  SECTION("Read some") {
    const std::string str{"Hej med dig"};
    REQUIRE_CALL(async_ssh::test::libssh2_api_mock_instance,
                 libssh2_channel_read_ex(ptr, 0, trompeloeil::_, 1024UL))
      .LR_SIDE_EFFECT(std::copy_n(str.data(), str.size(), _3))
      .RETURN(str.size());


    std::error_code ec;
    auto [channel, entry] = session.scp_recv(path, ec);
    std::array<char, 1024> mem{};
    auto read = channel.read_some(boost::asio::buffer(mem));
    CHECK(read == str.size());
    CHECK(std::string(mem.data(), read) == str);
  }

}
