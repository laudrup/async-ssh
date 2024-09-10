#ifndef ASYNC_SSH_CHANNEL_HPP
#define ASYNC_SSH_CHANNEL_HPP

#include <async_ssh/error.hpp>

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>
#include <async_ssh/detail/error.hpp>

#include <boost/system/error_code.hpp>

#include <cstdlib>
#include <memory>

namespace async_ssh {

namespace api = detail::libssh2_api;

/** The channel class represents an open SSH channel for receiving and
 * sending data to the remote server.
 *
 */
class channel {
public:
  ~channel() = default;
  channel(const channel&) = delete;
  channel& operator=(const channel&) = delete;
  channel(channel&&) noexcept = default;
  channel& operator=(channel&&) noexcept = default;

  /** Read some data from the channel.
   *
   * This function is used to read data from the channel. The function
   * call will block until one or more bytes of data has been read
   * successfully, or until an error occurs.
   *
   * @param ec Set to indicate what error occurred, if any.
   * @param buffers The buffers into which the data will be read.
   *
   * @returns The number of bytes read.
   *
   * @note The `read_some` operation may not read all of the requested
   * number of bytes. Consider using the `net::read` function if you
   * need to ensure that the requested amount of data is read before
   * the blocking operation completes.
   *
   * @see [libssh2_channel_read](https://libssh2.org/libssh2_channel_read.html)
   */
  template <class MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, std::error_code& ec) {
    size_t total_bytes_read = 0;
    for (auto&& buf : buffers) {
      auto rc = api::libssh2_channel_read(handle(), static_cast<char*>(buf.data()), buf.size());
      if (rc < 0) {
        ec = std::error_code(static_cast<int>(rc), libssh2_error_category());
        return total_bytes_read;
      }
      total_bytes_read += rc;
    }
    ec = {};
    return total_bytes_read;
  }

  /** Read some data from the channel.
   *
   * This function is used to read data from the channel. The function
   * call will block until one or more bytes of data has been read
   * successfully, or until an error occurs.
   *
   * @param buffers The buffers into which the data will be read.
   *
   * @returns The number of bytes read.
   *
   * @throws std::system_error Thrown on failure.
   *
   * @note The `read_some` operation may not read all of the requested
   * number of bytes. Consider using the `net::read` function if you
   * need to ensure that the requested amount of data is read before
   * the blocking operation completes.
   *
   * @see [libssh2_channel_read](https://libssh2.org/libssh2_channel_read.html)
   */
  template <class MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    std::error_code ec;
    auto bytes_read = read_some(buffers, ec);
    detail::throw_on_error(ec, "read_some");
    return bytes_read;
  }

  /** Get a pointer to the libssh2 channel being used by this object.
   *
   * @see [libssh2 docs](https://libssh2.org/docs.html)
   *
   * @return A pointer to the libssh2 channel. Ownership is not
   * transferred to the caller.
   */
  LIBSSH2_CHANNEL* handle() const {
    return channel_.get();
  }

private:
  template<class SocketType> friend class session;
  explicit channel(LIBSSH2_CHANNEL* libssh2_channel)
    : channel_(libssh2_channel, api::libssh2_channel_free) {
  }

  std::unique_ptr<LIBSSH2_CHANNEL, decltype(&detail::libssh2_api::libssh2_channel_free)> channel_;
};

} // namespace async_ssh

#endif // ASYNC_SSH_CHANNEL_HPP
