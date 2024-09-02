#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/trompeloeil.hpp>

void trompeloeil_error_reporter(trompeloeil::severity s, const char* file, unsigned long line, std::string const& msg) {
  std::ostringstream os;
  if (line != 0) {
    os << file << ':' << line << '\n';
  }
  os << msg;
  const auto failure = os.str();
  if (s == trompeloeil::severity::fatal) {
    FAIL(failure);
  } else {
    CAPTURE(failure);
    CHECK(failure.empty());
  }
}

void trompeloeil_success_reporter(const char* trompeloeil_mock_calls_done_correctly) {
  REQUIRE(trompeloeil_mock_calls_done_correctly != nullptr);
}

int main(const int argc, const char* const* argv) {
  trompeloeil::set_reporter(trompeloeil_error_reporter, trompeloeil_success_reporter);
  return Catch::Session().run(argc, argv);
}
