#ifndef ASYNC_SSH_CHANNEL_HPP
#define ASYNC_SSH_CHANNEL_HPP

#include <async_ssh/error.hpp>
#include <async_ssh/stream.hpp>

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
 */
template<class Socket>
class basic_channel {
public:

  /// Constructs a channel without any associated @ref session.
  basic_channel() = default;

  /// Destroys the channel and any open @ref stream.
  ~basic_channel() = default;

  /// Move construct a @ref channel from another.
  basic_channel(basic_channel&&) noexcept = default;

  /// Move assing a @ref channel from another.
  basic_channel& operator=(basic_channel&&) noexcept = default;

  basic_channel(const basic_channel&) = delete;
  basic_channel& operator=(const basic_channel&) = delete;

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

  /** Get a reference to the standard I/O substream for reading and
   * writing to and from the channel.
   *
   * @return A reference to the the standard I/O substream. Ownership
   * is not transferred to the caller.
   */
  stream<Socket>& std_stream() {
    return std_stream_;
  }

  /** Get a reference to the error I/O substream for reading and
   * writing to and from the channel.
   *
   * @return A reference to the the error I/O substream. Ownership is
   * not transferred to the caller.
   */
  stream<Socket>& err_stream() {
    return err_stream_;
  }

private:
  template<typename SocketType> friend class basic_session;

  basic_channel(LIBSSH2_CHANNEL* libssh2_channel, Socket& socket)
    : channel_(libssh2_channel, api::libssh2_channel_free)
    , std_stream_(&socket, channel_.get(), 0)
    , err_stream_(&socket, channel_.get(), SSH_EXTENDED_DATA_STDERR) {
  }

  std::unique_ptr<LIBSSH2_CHANNEL, decltype(&api::libssh2_channel_free)> channel_{nullptr, api::libssh2_channel_free};
  stream<Socket> std_stream_;
  stream<Socket> err_stream_;
};

} // namespace async_ssh

#endif // ASYNC_SSH_CHANNEL_HPP
