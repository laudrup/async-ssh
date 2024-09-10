#ifndef ASYNC_SSH_REMOTE_DIRECTORY_ENTRY_HPP
#define ASYNC_SSH_REMOTE_DIRECTORY_ENTRY_HPP

#include <async_ssh/detail/wincompat.hpp>

#include <libssh2.h>

#include <filesystem>

namespace async_ssh {
/** Represents a directory entry on the remote server.
 */
class remote_directory_entry {
public:
  /** Information about the type and permissions of a remote entry.
   *
   * @return The available entry status as returned from the remote
   * server.
   */
  std::filesystem::file_status status() const {
    namespace fs = std::filesystem;
    const auto mode = stat_.st_mode;
    if (S_ISLNK(mode)) {
      return fs::file_status(fs::file_type::symlink, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    if (S_ISDIR(mode)) {
      return fs::file_status(fs::file_type::directory, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    if (S_ISREG(mode)) {
      return fs::file_status(fs::file_type::regular, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    if (S_ISBLK(mode)){
      return fs::file_status(fs::file_type::block, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    if (S_ISCHR(mode)) {
      return fs::file_status(fs::file_type::character, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    if (S_ISFIFO(mode)) {
      return fs::file_status(fs::file_type::fifo, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    if (S_ISSOCK(mode)) {
      return fs::file_status(fs::file_type::socket, static_cast<fs::perms>(mode) & fs::perms::mask);
    }
    return fs::file_status(fs::file_type::unknown);
  }

  /** The size of the remote directory entry.
   *
   * @return The size of the entry (eg. a file) in bytes
   */
  std::size_t size() const {
    return stat_.st_size;
  }

private:
  template<class SocketType> friend class session;
  libssh2_struct_stat stat_{};
};
} // namespace async_ssh

#endif // ASYNC_SSH_REMOTE_DIRECTORY_ENTRY_HPP
