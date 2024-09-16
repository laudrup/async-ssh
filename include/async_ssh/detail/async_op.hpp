#ifndef ASYNC_SSH_DETAIL_ASYNC_OP_HPP
#define ASYNC_SSH_DETAIL_ASYNC_OP_HPP

#include <async_ssh/error.hpp>
#include <async_ssh/detail/libssh2_api.hpp>

#include <libssh2.h>

#include <boost/asio.hpp>

#include <system_error>

namespace async_ssh::detail {

namespace api = detail::libssh2_api;

template <class Socket, class Function>
struct async_op : boost::asio::coroutine {
  async_op(Socket& socket, LIBSSH2_SESSION* session, Function&& function)
    : socket_(socket)
    , session_(session)
    , function_(function) {
    api::libssh2_session_set_blocking(session_, 0);
  }

  template <typename Self>
  void operator()(Self& self, std::error_code ec = {}) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++entry_count_;
    auto is_continuation = [this] {
      return entry_count_ > 1;
    };

    int rc = 0;
    int dir = 0;
    BOOST_ASIO_CORO_REENTER(*this) {
      while((rc = function_(session_)) == LIBSSH2_ERROR_EAGAIN) {
        dir = api::libssh2_session_block_directions(session_);
        if(dir & LIBSSH2_SESSION_BLOCK_INBOUND) {
          BOOST_ASIO_CORO_YIELD {
            socket_.async_wait(boost::asio::ip::tcp::socket::wait_read, std::move(self));
          }
          continue;
        }
        if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
          BOOST_ASIO_CORO_YIELD {
            socket_.async_wait(boost::asio::ip::tcp::socket::wait_write, std::move(self));
          }
          continue;
        }
      }
      ec = std::error_code(rc, async_ssh::libssh2_error_category());
      if (!is_continuation()) {
        BOOST_ASIO_CORO_YIELD {
          auto e = self.get_executor();
          boost::asio::post(e, [self = std::move(self), ec]() mutable { self(ec); });
        }
      }
      self.complete(ec);
    }
  }

private:
  Socket& socket_;
  LIBSSH2_SESSION* session_;
  Function function_;
  int entry_count_{0};
};

} // namespace async_ssh::detail

#endif // ASYNC_SSH_DETAIL_ASYNC_OP_HPP
