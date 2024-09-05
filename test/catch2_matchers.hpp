#ifndef ASYNC_SSH_TEST_CATCH2_MATCHERS_HPP
#define ASYNC_SSH_TEST_CATCH2_MATCHERS_HPP

#include <system_error>

#include <catch2/matchers/catch_matchers_all.hpp>


namespace async_ssh::test {

namespace detail {

class system_error_matcher final : public Catch::Matchers::MatcherBase<std::system_error> {
public:
  explicit system_error_matcher(const std::error_code& ec)
    : ec_(ec) {
  }

  bool match(const std::system_error& ex) const override {
    return ex.code() == ec_;
  }

  std::string describe() const override {
    return std::string("Error code matches: ") + ec_.message();
  }

private:
  std::error_code ec_;
};

} // namespace detail

inline detail::system_error_matcher error_code_matches(const std::error_code& ec) {
  return detail::system_error_matcher{ec};
}

}  // namespace async_ssh::test

#endif // ASYNC_SSH_TEST_CATCH2_MATCHERS_HPP
