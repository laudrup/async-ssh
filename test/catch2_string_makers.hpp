#ifndef ASYNC_SSH_TEST_CATCH2_STRING_MAKERS_HPP
#define ASYNC_SSH_TEST_CATCH2_STRING_MAKERS_HPP

#include <catch2/catch_tostring.hpp>

#include <filesystem>

namespace Catch {
    template<>
    struct StringMaker<std::filesystem::file_type> {
        static std::string convert(const std::filesystem::file_type& value) {
          switch (value) {
            case std::filesystem::file_type::none:
              return "none";
            case std::filesystem::file_type::not_found:
              return "not_found";
            case std::filesystem::file_type::regular:
              return "regular";
            case std::filesystem::file_type::directory:
              return "directory";
            case std::filesystem::file_type::symlink:
              return "symlink";
            case std::filesystem::file_type::block:
              return "block";
            case std::filesystem::file_type::character:
              return "character";
            case std::filesystem::file_type::fifo:
              return "fifo";
            case std::filesystem::file_type::socket:
              return "socket";
            case std::filesystem::file_type::unknown:
              return "unknown";
          }
          return "unknown";
        }
    };
} // namespace Catch

#endif // ASYNC_SSH_TEST_CATCH2_STRING_MAKERS_HPP
