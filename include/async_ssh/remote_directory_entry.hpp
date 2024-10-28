#ifndef ASYNC_SSH_REMOTE_DIRECTORY_ENTRY_HPP
#define ASYNC_SSH_REMOTE_DIRECTORY_ENTRY_HPP

#include <libssh2.h>

#include <chrono>
#include <filesystem>

namespace async_ssh {
namespace detail {
  template<class SocketType> struct async_scp_recv;
} // namespace detail

/** Represents information on a directory entry on the remote server.
 */
class remote_directory_entry {
public:
  remote_directory_entry() = default;
  remote_directory_entry(const remote_directory_entry&) = default;
  remote_directory_entry& operator=(const remote_directory_entry&) = default;
  remote_directory_entry(remote_directory_entry&&) = default;
  remote_directory_entry& operator=(remote_directory_entry&&) = default;

  /** Returns the permissions of the remote entry.
   *
   * @return The available entry permissions as returned from the
   * remote server.
   */
  std::filesystem::perms permissions() const {
    return std::filesystem::perms(stat_.st_mode);
  }

  /** Returns the time of the last modification of the remote entry.
   *
   * @return The last time the remote entry was modified.
   */
  std::chrono::system_clock::time_point last_write_time() const {
    return std::chrono::system_clock::from_time_t(stat_.st_mtime);
  }

  /** Returns the time of the last access of the remote entry.
   *
   * @return The last time the remote entry was accessed.
   */
  std::chrono::system_clock::time_point last_access_time() const {
    return std::chrono::system_clock::from_time_t(stat_.st_atime);
  }

  /** Returns the size of the remote entry.
   *
   * @return The size of the entry (ie. the file) in bytes
   */
  std::size_t size() const {
    return stat_.st_size;
  }

private:
  template<typename Socket> friend class session;
  libssh2_struct_stat stat_{};
};
} // namespace async_ssh

#endif // ASYNC_SSH_REMOTE_DIRECTORY_ENTRY_HPP
