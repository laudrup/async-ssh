#ifndef ASYNC_SSH_STREAM_HPP
#define ASYNC_SSH_STREAM_HPP

#include <async_ssh/channel.hpp>

#include <async_ssh/detail/error.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <boost/asio.hpp>

#include <type_traits>

namespace async_ssh {

namespace api = detail::libssh2_api;

/** The stream class represents an active channel stream from an
 * open SSH channel satisfying the Asio
 * [SyncReadStream](https://www.boost.org/doc/libs/release/doc/html/boost_asio/reference/SyncReadStream.html)
 * requirements.
 *
 */
template<class Socket>
class stream {
public:
  /// The type of the socket.
  using socket_type = typename std::remove_reference<Socket>::type;

  /// The type of the executor associated with the object.
  using executor_type = typename std::remove_reference<socket_type>::type::executor_type;

  /// Constructs a stream without any associated @ref channel.
  stream() = default;

  /// Destroys the stream.
  ~stream() = default;

  /// Move construct a @ref stream from another.
  stream(stream&&) noexcept = default;

  /// Move assing a @ref stream from another
  stream& operator=(stream&&) noexcept = default;

  stream(const stream&) = delete;
  stream& operator=(const stream&) = delete;

  /** Read some data from the stream.
   *
   * This function is used to read data from the stream. The function
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
      auto rc = api::libssh2_channel_read_ex(channel_, stream_id_, static_cast<char*>(buf.data()), buf.size());
      if (rc < 0) {
        ec = std::error_code(static_cast<int>(rc), libssh2_error_category());
        return total_bytes_read;
      }
      total_bytes_read += rc;
    }
    ec = {};
    return total_bytes_read;
  }

  /** Read some data from the stream.
   *
   * This function is used to read data from the stream. The function
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

private:
  template<typename SocketType> friend class basic_channel;

  stream(socket_type* socket, LIBSSH2_CHANNEL* channel, int stream_id)
    : socket_(socket)
    , channel_(channel)
    , stream_id_(stream_id) {
  }

  socket_type* socket_ = nullptr;
  LIBSSH2_CHANNEL* channel_ = nullptr;
  int stream_id_{0};
};

} // namespace async_ssh

#endif // ASYNC_SSH_STREAM_HPP
