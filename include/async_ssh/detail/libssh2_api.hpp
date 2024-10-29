#ifndef ASYNC_SSH_DETAIL_LIBSSH2_API_HPP
#define ASYNC_SSH_DETAIL_LIBSSH2_API_HPP

#include <libssh2.h>

namespace async_ssh::detail::libssh2_api {

int libssh2_init(int flags);

void libssh2_exit(void);

void libssh2_free(LIBSSH2_SESSION *session, void *ptr);

int libssh2_session_supported_algs(LIBSSH2_SESSION* session,
                                   int method_type,
                                   const char ***algs);

typedef void* (*libssh2_alloc_func)(size_t count, void **abstract);
typedef void (*libssh2_free_func)(void *ptr, void **abstract);
typedef void* (*libssh2_realloc_func)(void *ptr, size_t count, void **abstract);

LIBSSH2_SESSION* libssh2_session_init_ex(libssh2_alloc_func my_alloc,
                                         libssh2_free_func my_free,
                                         libssh2_realloc_func my_realloc,
                                         void *abstract);

void** libssh2_session_abstract(LIBSSH2_SESSION *session);

int libssh2_banner_set(LIBSSH2_SESSION *session,
                       const char *banner);

int libssh2_session_handshake(LIBSSH2_SESSION *session,
                              libssh2_socket_t sock);

int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session,
                                  int reason,
                                  const char *description,
                                  const char *lang);

int libssh2_session_free(LIBSSH2_SESSION *session);

const char* libssh2_hostkey_hash(LIBSSH2_SESSION *session,
                                 int hash_type);

const char* libssh2_session_hostkey(LIBSSH2_SESSION *session,
                                    size_t *len, int *type);

int libssh2_session_method_pref(LIBSSH2_SESSION *session,
                                int method_type,
                                const char *prefs);

const char* libssh2_session_methods(LIBSSH2_SESSION *session,
                                    int method_type);

int libssh2_session_last_error(LIBSSH2_SESSION *session,
                               char **errmsg,
                               int *errmsg_len, int want_buf);

int libssh2_session_last_errno(LIBSSH2_SESSION *session);

int libssh2_session_set_last_error(LIBSSH2_SESSION* session,
                                   int errcode,
                                   const char *errmsg);

int libssh2_session_block_directions(LIBSSH2_SESSION *session);

int libssh2_session_flag(LIBSSH2_SESSION *session, int flag,
                         int value);

const char* libssh2_session_banner_get(LIBSSH2_SESSION *session);


char* libssh2_userauth_list(LIBSSH2_SESSION *session,
                            const char *username,
                            unsigned int username_len);

int libssh2_userauth_authenticated(LIBSSH2_SESSION *session);

typedef void (*libssh2_passwd_changereq_func)(LIBSSH2_SESSION *session, char **newpw, int *newpw_len, void **abstract);

int libssh2_userauth_password_ex(LIBSSH2_SESSION *session,
                                 const char *username,
                                 unsigned int username_len,
                                 const char *password,
                                 unsigned int password_len,
                                 libssh2_passwd_changereq_func passwd_change_cb);

int libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION *session,
                                           const char *username,
                                           unsigned int username_len,
                                           const char *publickey,
                                           const char *privatekey,
                                           const char *passphrase);

typedef int (*libssh2_sign_callback_func)(LIBSSH2_SESSION *session, unsigned char **sig, size_t *sig_len, const unsigned char *data, size_t data_len, void **abstract);

int libssh2_userauth_publickey(LIBSSH2_SESSION *session,
                               const char *username,
                               const unsigned char *pubkeydata,
                               size_t pubkeydata_len,
                               libssh2_sign_callback_func sign_callback,
                               void **abstract);

int libssh2_userauth_hostbased_fromfile_ex(LIBSSH2_SESSION *session,
                                           const char *username,
                                           unsigned int username_len,
                                           const char *publickey,
                                           const char *privatekey,
                                           const char *passphrase,
                                           const char *hostname,
                                           unsigned int hostname_len,
                                           const char *local_username,
                                           unsigned int local_username_len);

int libssh2_userauth_publickey_frommemory(LIBSSH2_SESSION *session,
                                          const char *username,
                                          size_t username_len,
                                          const char *publickeyfiledata,
                                          size_t publickeyfiledata_len,
                                          const char *privatekeyfiledata,
                                          size_t privatekeyfiledata_len,
                                          const char *passphrase);

typedef void (*libssh2_userauth_kbdint_response_func)(const char *name, int name_len, const char *instruction, int instruction_len, int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract);

int libssh2_userauth_keyboard_interactive_ex(LIBSSH2_SESSION* session,
                                             const char *username,
                                             unsigned int username_len,
                                             libssh2_userauth_kbdint_response_func response_callback);

int libssh2_poll(LIBSSH2_POLLFD *fds, unsigned int nfds, long timeout);

LIBSSH2_CHANNEL* libssh2_channel_open_ex(LIBSSH2_SESSION *session, const char *channel_type,
                                         unsigned int channel_type_len,
                                         unsigned int window_size, unsigned int packet_size,
                                         const char *message, unsigned int message_len);


LIBSSH2_CHANNEL* libssh2_channel_direct_tcpip_ex(LIBSSH2_SESSION *session, const char *host,
                                                 int port, const char *shost, int sport);

LIBSSH2_LISTENER* libssh2_channel_forward_listen_ex(LIBSSH2_SESSION *session, const char *host,
                                                    int port, int *bound_port,
                                                    int queue_maxsize);

int libssh2_channel_forward_cancel(LIBSSH2_LISTENER *listener);

LIBSSH2_CHANNEL* libssh2_channel_forward_accept(LIBSSH2_LISTENER *listener);

int libssh2_channel_setenv_ex(LIBSSH2_CHANNEL *channel,
                              const char *varname,
                              unsigned int varname_len,
                              const char *value,
                              unsigned int value_len);

int libssh2_channel_request_auth_agent(LIBSSH2_CHANNEL *channel);

int libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL *channel,
                                   const char *term,
                                   unsigned int term_len,
                                   const char *modes,
                                   unsigned int modes_len,
                                   int width, int height,
                                   int width_px, int height_px);

int libssh2_channel_request_pty_size_ex(LIBSSH2_CHANNEL *channel,
                                        int width, int height,
                                        int width_px,
                                        int height_px);

int libssh2_channel_x11_req_ex(LIBSSH2_CHANNEL *channel,
                               int single_connection,
                               const char *auth_proto,
                               const char *auth_cookie,
                               int screen_number);

int libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel,
                                    const char *request,
                                    unsigned int request_len,
                                    const char *message,
                                    unsigned int message_len);

ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel,
                                int stream_id, char *buf,
                                size_t buflen);

int libssh2_poll_channel_read(LIBSSH2_CHANNEL *channel,
                              int extended);

unsigned long libssh2_channel_window_read_ex(LIBSSH2_CHANNEL *channel,
                                             unsigned long *read_avail,
                                             unsigned long *window_size_initial);

int libssh2_channel_receive_window_adjust2(LIBSSH2_CHANNEL *channel,
                                           unsigned long adjustment,
                                           unsigned char force,
                                           unsigned int *storewindow);

ssize_t libssh2_channel_write_ex(LIBSSH2_CHANNEL *channel,
                                 int stream_id, const char *buf,
                                 size_t buflen);

unsigned long libssh2_channel_window_write_ex(LIBSSH2_CHANNEL *channel,
                                              unsigned long *window_size_initial);

void libssh2_session_set_blocking(LIBSSH2_SESSION* session, int blocking);

int libssh2_session_get_blocking(LIBSSH2_SESSION* session);

void libssh2_channel_set_blocking(LIBSSH2_CHANNEL *channel, int blocking);

void libssh2_session_set_timeout(LIBSSH2_SESSION* session, long timeout);

long libssh2_session_get_timeout(LIBSSH2_SESSION* session);


int libssh2_channel_handle_extended_data2(LIBSSH2_CHANNEL *channel,
                                          int ignore_mode);

int libssh2_channel_flush_ex(LIBSSH2_CHANNEL *channel,
                             int streamid);

int libssh2_channel_get_exit_status(LIBSSH2_CHANNEL* channel);

int libssh2_channel_get_exit_signal(LIBSSH2_CHANNEL* channel,
                                    char **exitsignal,
                                    size_t *exitsignal_len,
                                    char **errmsg,
                                    size_t *errmsg_len,
                                    char **langtag,
                                    size_t *langtag_len);

int libssh2_channel_send_eof(LIBSSH2_CHANNEL *channel);

int libssh2_channel_eof(LIBSSH2_CHANNEL *channel);

int libssh2_channel_wait_eof(LIBSSH2_CHANNEL *channel);

int libssh2_channel_close(LIBSSH2_CHANNEL *channel);

int libssh2_channel_wait_closed(LIBSSH2_CHANNEL *channel);

int libssh2_channel_free(LIBSSH2_CHANNEL *channel);

LIBSSH2_CHANNEL* libssh2_scp_recv2(LIBSSH2_SESSION *session,
                                   const char *path,
                                   libssh2_struct_stat *sb);

LIBSSH2_CHANNEL *libssh2_scp_send_ex(LIBSSH2_SESSION *session,
                                     const char *path, int mode,
                                     size_t size, long mtime,
                                     long atime);

LIBSSH2_CHANNEL* libssh2_scp_send64(LIBSSH2_SESSION *session, const char *path, int mode,
                                    libssh2_int64_t size, time_t mtime, time_t atime);

int libssh2_base64_decode(LIBSSH2_SESSION *session, char **dest,
                          unsigned int *dest_len,
                          const char *src, unsigned int src_len);

const char *libssh2_version(int req_version_num);

LIBSSH2_KNOWNHOSTS* libssh2_knownhost_init(LIBSSH2_SESSION *session);

int libssh2_knownhost_add(LIBSSH2_KNOWNHOSTS *hosts,
                          const char *host,
                          const char *salt,
                          const char *key, size_t keylen, int typemask,
                          struct libssh2_knownhost **store);

int libssh2_knownhost_addc(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *host,
                           const char *salt,
                           const char *key, size_t keylen,
                           const char *comment, size_t commentlen, int typemask,
                           struct libssh2_knownhost **store);

int libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,
                            const char *host, const char *key, size_t keylen,
                            int typemask,
                            struct libssh2_knownhost **knownhost);

int libssh2_knownhost_checkp(LIBSSH2_KNOWNHOSTS *hosts,
                             const char *host, int port,
                             const char *key, size_t keylen,
                             int typemask,
                             struct libssh2_knownhost **knownhost);

int libssh2_knownhost_del(LIBSSH2_KNOWNHOSTS *hosts,
                          struct libssh2_knownhost *entry);

void libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS *hosts);

int libssh2_knownhost_readline(LIBSSH2_KNOWNHOSTS *hosts,
                               const char *line, size_t len, int type);

int libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS *hosts,
                               const char *filename, int type);

int libssh2_knownhost_writeline(LIBSSH2_KNOWNHOSTS *hosts,
                                struct libssh2_knownhost *known,
                                char *buffer, size_t buflen,
                                size_t *outlen,
                                int type);

int libssh2_knownhost_writefile(LIBSSH2_KNOWNHOSTS *hosts,
                                const char *filename, int type);

int libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS *hosts,
                          struct libssh2_knownhost **store,
                          struct libssh2_knownhost *prev);

LIBSSH2_AGENT* libssh2_agent_init(LIBSSH2_SESSION *session);

int libssh2_agent_connect(LIBSSH2_AGENT *agent);

int libssh2_agent_list_identities(LIBSSH2_AGENT *agent);

int libssh2_agent_get_identity(LIBSSH2_AGENT *agent,
                               struct libssh2_agent_publickey **store,
                               struct libssh2_agent_publickey *prev);

int libssh2_agent_userauth(LIBSSH2_AGENT *agent,
                           const char *username,
                           struct libssh2_agent_publickey *identity);

int libssh2_agent_disconnect(LIBSSH2_AGENT *agent);

void libssh2_agent_free(LIBSSH2_AGENT *agent);

void libssh2_agent_set_identity_path(LIBSSH2_AGENT *agent,
                                     const char *path);

const char* libssh2_agent_get_identity_path(LIBSSH2_AGENT *agent);

void libssh2_keepalive_config(LIBSSH2_SESSION *session,
                              int want_reply,
                              unsigned interval);

int libssh2_keepalive_send(LIBSSH2_SESSION *session,
                           int *seconds_to_next);

int libssh2_trace(LIBSSH2_SESSION *session, int bitmask);

typedef void (*libssh2_trace_handler_func)(LIBSSH2_SESSION*,
                                           void *,
                                           const char *,
                                           size_t);

int libssh2_trace_sethandler(LIBSSH2_SESSION *session,
                             void *context,
                             libssh2_trace_handler_func callback);

} // namespace async_ssh::detail::libssh2_api

#ifndef ASYNC_SSH_MOCK_LIBSSH2_API
#include <async_ssh/detail/impl/libssh2_api.ipp>
#endif // ASYNC_SSH_MOCK_LIBSSH2_API

#endif // ASYNC_SSH_DETAIL_LIBSSH2_API_HPP
