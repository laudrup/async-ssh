#ifndef ASYNC_SSH_TEST_LIBSSH2_API_MOCK_HPP
#define ASYNC_SSH_TEST_LIBSSH2_API_MOCK_HPP

#include <trompeloeil.hpp>

#include <async_ssh/detail/libssh2_api.hpp>

namespace async_ssh::test {

class libssh2_api_mock {
public:
  MAKE_MOCK1(libssh2_init, int(int));
  MAKE_MOCK0(libssh2_exit, void());
  MAKE_MOCK2(libssh2_free, void(LIBSSH2_SESSION *, void *));
  MAKE_MOCK3(libssh2_session_supported_algs,
             int(LIBSSH2_SESSION *, int, const char ***));
  MAKE_MOCK4(libssh2_session_init_ex,
             LIBSSH2_SESSION *(async_ssh::detail::libssh2_api::libssh2_alloc_func,
                               async_ssh::detail::libssh2_api::libssh2_free_func,
                               async_ssh::detail::libssh2_api::libssh2_realloc_func,
                               void *));
  MAKE_MOCK1(libssh2_session_abstract, void **(LIBSSH2_SESSION *));
  MAKE_MOCK3(libssh2_session_callback_set,
             void *(LIBSSH2_SESSION *, int, void *));
  MAKE_MOCK2(libssh2_session_banner_set, int(LIBSSH2_SESSION *, const char *));
  MAKE_MOCK2(libssh2_banner_set, int(LIBSSH2_SESSION *, const char *));
  MAKE_MOCK2(libssh2_session_startup, int(LIBSSH2_SESSION *, int));
  MAKE_MOCK2(libssh2_session_handshake,
             int(LIBSSH2_SESSION *, libssh2_socket_t));
  MAKE_MOCK4(libssh2_session_disconnect_ex,
             int(LIBSSH2_SESSION *, int, const char *, const char *));
  MAKE_MOCK1(libssh2_session_free, int(LIBSSH2_SESSION *));
  MAKE_MOCK2(libssh2_hostkey_hash, const char *(LIBSSH2_SESSION *, int));
  MAKE_MOCK3(libssh2_session_hostkey,
             const char *(LIBSSH2_SESSION *, size_t *, int *));
  MAKE_MOCK3(libssh2_session_method_pref,
             int(LIBSSH2_SESSION *, int, const char *));
  MAKE_MOCK2(libssh2_session_methods, const char *(LIBSSH2_SESSION *, int));
  MAKE_MOCK4(libssh2_session_last_error,
             int(LIBSSH2_SESSION *, char **, int *, int));
  MAKE_MOCK1(libssh2_session_last_errno, int(LIBSSH2_SESSION *));
  MAKE_MOCK3(libssh2_session_set_last_error,
             int(LIBSSH2_SESSION *, int, const char *));
  MAKE_MOCK1(libssh2_session_block_directions, int(LIBSSH2_SESSION *));
  MAKE_MOCK3(libssh2_session_flag, int(LIBSSH2_SESSION *, int, int));
  MAKE_MOCK1(libssh2_session_banner_get, const char *(LIBSSH2_SESSION *));
  MAKE_MOCK3(libssh2_userauth_list,
             char *(LIBSSH2_SESSION *, const char *, unsigned int));
  MAKE_MOCK1(libssh2_userauth_authenticated, int(LIBSSH2_SESSION *));
  MAKE_MOCK6(libssh2_userauth_password_ex,
             int(LIBSSH2_SESSION *, const char *, unsigned int, const char *,
                 unsigned int, async_ssh::detail::libssh2_api::libssh2_passwd_changereq_func));
  MAKE_MOCK6(libssh2_userauth_publickey_fromfile_ex,
             int(LIBSSH2_SESSION *, const char *, unsigned int, const char *,
                 const char *, const char *));
  MAKE_MOCK6(libssh2_userauth_publickey,
             int(LIBSSH2_SESSION *, const char *, const unsigned char *, size_t,
                 async_ssh::detail::libssh2_api::libssh2_sign_callback_func, void **));
  MAKE_MOCK10(libssh2_userauth_hostbased_fromfile_ex,
              int(LIBSSH2_SESSION *, const char *, unsigned int, const char *,
                  const char *, const char *, const char *, unsigned int,
                  const char *, unsigned int));
  MAKE_MOCK8(libssh2_userauth_publickey_frommemory,
             int(LIBSSH2_SESSION *, const char *, size_t, const char *, size_t,
                 const char *, size_t, const char *));
  MAKE_MOCK4(libssh2_userauth_keyboard_interactive_ex,
             int(LIBSSH2_SESSION *, const char *, unsigned int,
                 async_ssh::detail::libssh2_api::libssh2_userauth_kbdint_response_func));
  MAKE_MOCK3(libssh2_poll, int(LIBSSH2_POLLFD *, unsigned int, long));
  MAKE_MOCK7(libssh2_channel_open_ex,
             LIBSSH2_CHANNEL *(LIBSSH2_SESSION *, const char *, unsigned int,
                               unsigned int, unsigned int, const char *,
                               unsigned int));
  MAKE_MOCK5(libssh2_channel_direct_tcpip_ex,
             LIBSSH2_CHANNEL *(LIBSSH2_SESSION *, const char *, int,
                               const char *, int));
  MAKE_MOCK5(libssh2_channel_forward_listen_ex,
             LIBSSH2_LISTENER *(LIBSSH2_SESSION *, const char *, int, int *,
                                int));
  MAKE_MOCK1(libssh2_channel_forward_cancel, int(LIBSSH2_LISTENER *));
  MAKE_MOCK1(libssh2_channel_forward_accept,
             LIBSSH2_CHANNEL *(LIBSSH2_LISTENER *));
  MAKE_MOCK5(libssh2_channel_setenv_ex,
             int(LIBSSH2_CHANNEL *, const char *, unsigned int, const char *,
                 unsigned int));
  MAKE_MOCK1(libssh2_channel_request_auth_agent, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK9(libssh2_channel_request_pty_ex,
             int(LIBSSH2_CHANNEL *, const char *, unsigned int, const char *,
                 unsigned int, int, int, int, int));
  MAKE_MOCK5(libssh2_channel_request_pty_size_ex,
             int(LIBSSH2_CHANNEL *, int, int, int, int));
  MAKE_MOCK5(libssh2_channel_x11_req_ex,
             int(LIBSSH2_CHANNEL *, int, const char *, const char *, int));
  MAKE_MOCK5(libssh2_channel_process_startup,
             int(LIBSSH2_CHANNEL *, const char *, unsigned int, const char *,
                 unsigned int));
  MAKE_MOCK4(libssh2_channel_read_ex,
             ssize_t(LIBSSH2_CHANNEL *, int, char *, size_t));
  MAKE_MOCK2(libssh2_poll_channel_read, int(LIBSSH2_CHANNEL *, int));
  MAKE_MOCK3(libssh2_channel_window_read_ex,
             unsigned long(LIBSSH2_CHANNEL *, unsigned long *,
                           unsigned long *));
  MAKE_MOCK3(libssh2_channel_receive_window_adjust,
             unsigned long(LIBSSH2_CHANNEL *, unsigned long, unsigned char));
  MAKE_MOCK4(libssh2_channel_receive_window_adjust2,
             int(LIBSSH2_CHANNEL *, unsigned long, unsigned char,
                 unsigned int *));
  MAKE_MOCK4(libssh2_channel_write_ex,
             ssize_t(LIBSSH2_CHANNEL *, int, const char *, size_t));
  MAKE_MOCK2(libssh2_channel_window_write_ex,
             unsigned long(LIBSSH2_CHANNEL *, unsigned long *));
  MAKE_MOCK2(libssh2_session_set_blocking, void(LIBSSH2_SESSION *, int));
  MAKE_MOCK1(libssh2_session_get_blocking, int(LIBSSH2_SESSION *));
  MAKE_MOCK2(libssh2_channel_set_blocking, void(LIBSSH2_CHANNEL *, int));
  MAKE_MOCK2(libssh2_session_set_timeout, void(LIBSSH2_SESSION *, long));
  MAKE_MOCK1(libssh2_session_get_timeout, long(LIBSSH2_SESSION *));
  MAKE_MOCK2(libssh2_channel_handle_extended_data,
             void(LIBSSH2_CHANNEL *, int));
  MAKE_MOCK2(libssh2_channel_handle_extended_data2,
             int(LIBSSH2_CHANNEL *, int));
  MAKE_MOCK2(libssh2_channel_flush_ex, int(LIBSSH2_CHANNEL *, int));
  MAKE_MOCK1(libssh2_channel_get_exit_status, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK7(libssh2_channel_get_exit_signal,
             int(LIBSSH2_CHANNEL *, char **, size_t *, char **, size_t *,
                 char **, size_t *));
  MAKE_MOCK1(libssh2_channel_send_eof, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK1(libssh2_channel_eof, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK1(libssh2_channel_wait_eof, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK1(libssh2_channel_close, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK1(libssh2_channel_wait_closed, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK1(libssh2_channel_free, int(LIBSSH2_CHANNEL *));
  MAKE_MOCK3(libssh2_scp_recv,
             LIBSSH2_CHANNEL *(LIBSSH2_SESSION *, const char *, struct stat *));
  MAKE_MOCK3(libssh2_scp_recv2,
             LIBSSH2_CHANNEL *(LIBSSH2_SESSION *, const char *,
                               libssh2_struct_stat *));
  MAKE_MOCK6(libssh2_scp_send_ex,
             LIBSSH2_CHANNEL *(LIBSSH2_SESSION *, const char *, int, size_t,
                               long, long));
  MAKE_MOCK6(libssh2_scp_send64,
             LIBSSH2_CHANNEL *(LIBSSH2_SESSION *, const char *, int,
                               libssh2_int64_t, time_t, time_t));
  MAKE_MOCK5(libssh2_base64_decode,
             int(LIBSSH2_SESSION *, char **, unsigned int *, const char *,
                 unsigned int));
  MAKE_MOCK1(libssh2_version, const char *(int));
  MAKE_MOCK1(libssh2_knownhost_init, LIBSSH2_KNOWNHOSTS *(LIBSSH2_SESSION *));
  MAKE_MOCK7(libssh2_knownhost_add,
             int(LIBSSH2_KNOWNHOSTS *, const char *, const char *, const char *,
                 size_t, int, struct libssh2_knownhost **));
  MAKE_MOCK9(libssh2_knownhost_addc,
             int(LIBSSH2_KNOWNHOSTS *, const char *, const char *, const char *,
                 size_t, const char *, size_t, int,
                 struct libssh2_knownhost **));
  MAKE_MOCK6(libssh2_knownhost_check,
             int(LIBSSH2_KNOWNHOSTS *, const char *, const char *, size_t, int,
                 struct libssh2_knownhost **));
  MAKE_MOCK7(libssh2_knownhost_checkp,
             int(LIBSSH2_KNOWNHOSTS *, const char *, int, const char *, size_t,
                 int, struct libssh2_knownhost **));
  MAKE_MOCK2(libssh2_knownhost_del,
             int(LIBSSH2_KNOWNHOSTS *, struct libssh2_knownhost *));
  MAKE_MOCK1(libssh2_knownhost_free, void(LIBSSH2_KNOWNHOSTS *));
  MAKE_MOCK4(libssh2_knownhost_readline,
             int(LIBSSH2_KNOWNHOSTS *, const char *, size_t, int));
  MAKE_MOCK3(libssh2_knownhost_readfile,
             int(LIBSSH2_KNOWNHOSTS *, const char *, int));
  MAKE_MOCK6(libssh2_knownhost_writeline,
             int(LIBSSH2_KNOWNHOSTS *, struct libssh2_knownhost *, char *,
                 size_t, size_t *, int));
  MAKE_MOCK3(libssh2_knownhost_writefile,
             int(LIBSSH2_KNOWNHOSTS *, const char *, int));
  MAKE_MOCK3(libssh2_knownhost_get,
             int(LIBSSH2_KNOWNHOSTS *, struct libssh2_knownhost **,
                 struct libssh2_knownhost *));
  MAKE_MOCK1(libssh2_agent_init, LIBSSH2_AGENT *(LIBSSH2_SESSION *));
  MAKE_MOCK1(libssh2_agent_connect, int(LIBSSH2_AGENT *));
  MAKE_MOCK1(libssh2_agent_list_identities, int(LIBSSH2_AGENT *));
  MAKE_MOCK3(libssh2_agent_get_identity,
             int(LIBSSH2_AGENT *, struct libssh2_agent_publickey **,
                 struct libssh2_agent_publickey *));
  MAKE_MOCK3(libssh2_agent_userauth, int(LIBSSH2_AGENT *, const char *,
                                         struct libssh2_agent_publickey *));
  MAKE_MOCK1(libssh2_agent_disconnect, int(LIBSSH2_AGENT *));
  MAKE_MOCK1(libssh2_agent_free, void(LIBSSH2_AGENT *));
  MAKE_MOCK2(libssh2_agent_set_identity_path,
             void(LIBSSH2_AGENT *, const char *));
  MAKE_MOCK1(libssh2_agent_get_identity_path, const char *(LIBSSH2_AGENT *));
  MAKE_MOCK3(libssh2_keepalive_config, void(LIBSSH2_SESSION *, int, unsigned));
  MAKE_MOCK2(libssh2_keepalive_send, int(LIBSSH2_SESSION *, int *));
  MAKE_MOCK2(libssh2_trace, int(LIBSSH2_SESSION *, int));
  MAKE_MOCK3(libssh2_trace_sethandler,
             int(LIBSSH2_SESSION *, void *, async_ssh::detail::libssh2_api::libssh2_trace_handler_func));
};

extern libssh2_api_mock libssh2_api_mock_instance;
} // namespace async_ssh::test

#endif // ASYNC_SSH_TEST_LIBSSH2_API_MOCK_HPP
