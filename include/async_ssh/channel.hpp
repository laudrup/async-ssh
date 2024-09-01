#ifndef ASYNC_SSH_CHANNEL_HPP
#define ASYNC_SSH_CHANNEL_HPP

#include <async_ssh/detail/libssh2_init.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <boost/system/error_code.hpp>

#include <cstdlib>
#include <memory>
#include <stdexcept>

namespace async_ssh {

namespace api = detail::libssh2_api;

class channel {
public:
  channel(LIBSSH2_CHANNEL* channel, LIBSSH2_SESSION* session)
    : channel_(channel, api::libssh2_channel_free) {
    if (!channel_) {
      throw std::runtime_error("Unable to open a channel: " + std::to_string(libssh2_session_last_errno(session)));
    }
  }
  ~channel() = default;
  channel(const channel&) = delete;
  channel& operator=(const channel&) = delete;
  channel(channel&&) noexcept = default;
  channel& operator=(channel&&) noexcept = default;

  template <class MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code&) {
    return read_some(buffers);
  }

  template <class MutableBufferSequence>
  size_t read_some(const MutableBufferSequence& buffers) {
    size_t total_bytes_read = 0;
    for (auto&& buf : buffers) {
      total_bytes_read += api::libssh2_channel_read(handle(), static_cast<char*>(buf.data()), buf.size());
    }
    return total_bytes_read;
  }

  LIBSSH2_CHANNEL* handle() const {
    return channel_.get();
  }

  bool eof() const {
    const auto rc = api::libssh2_channel_eof(handle());
    if (rc < 0) {
      throw std::runtime_error("Failure checking channel EOF status: " + std::to_string(rc));
    }
    return rc == 1;
  }

private:
  std::unique_ptr<LIBSSH2_CHANNEL, decltype(&detail::libssh2_api::libssh2_channel_free)> channel_;
};

} // namespace async_ssh

#endif // ASYNC_SSH_CHANNEL_HPP
