#include "libssh2_api_mock.hpp"

namespace async_ssh {
namespace test {
libssh2_api_mock libssh2_api_mock_instance;
} // namespace test

namespace detail::libssh2_api {

int libssh2_init(int flags) {
  return test::libssh2_api_mock_instance.libssh2_init(flags);
}

void libssh2_exit() {
  return test::libssh2_api_mock_instance.libssh2_exit();
}

void libssh2_free(LIBSSH2_SESSION* session, void* ptr) {
  return test::libssh2_api_mock_instance.libssh2_free(session, ptr);
}

int libssh2_session_supported_algs(LIBSSH2_SESSION* session, int method_type, const char*** algs) {
  return test::libssh2_api_mock_instance.libssh2_session_supported_algs(session, method_type, algs);
}

LIBSSH2_SESSION* libssh2_session_init_ex(libssh2_alloc_func my_alloc, libssh2_free_func my_free, libssh2_realloc_func my_realloc, void* abstract) {
  return test::libssh2_api_mock_instance.libssh2_session_init_ex(my_alloc, my_free, my_realloc, abstract);
}

void** libssh2_session_abstract(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_abstract(session);
}

int libssh2_session_banner_set(LIBSSH2_SESSION* session, const char* banner) {
  return test::libssh2_api_mock_instance.libssh2_session_banner_set(session, banner);
}

int libssh2_session_handshake(LIBSSH2_SESSION* session, libssh2_socket_t sock) {
  return test::libssh2_api_mock_instance.libssh2_session_handshake(session, sock);
}

int libssh2_session_disconnect_ex(LIBSSH2_SESSION* session, int reason, const char* description, const char* lang) {
  return test::libssh2_api_mock_instance.libssh2_session_disconnect_ex(session, reason, description, lang);
}

int libssh2_session_free(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_free(session);
}

const char* libssh2_hostkey_hash(LIBSSH2_SESSION* session, int hash_type) {
  return test::libssh2_api_mock_instance.libssh2_hostkey_hash(session, hash_type);
}

const char* libssh2_session_hostkey(LIBSSH2_SESSION* session, size_t* len, int* type) {
  return test::libssh2_api_mock_instance.libssh2_session_hostkey(session, len, type);
}

int libssh2_session_method_pref(LIBSSH2_SESSION* session, int method_type, const char* prefs) {
  return test::libssh2_api_mock_instance.libssh2_session_method_pref(session, method_type, prefs);
}

const char* libssh2_session_methods(LIBSSH2_SESSION* session, int method_type) {
  return test::libssh2_api_mock_instance.libssh2_session_methods(session, method_type);
}

int libssh2_session_last_error(LIBSSH2_SESSION* session, char** errmsg, int* errmsg_len, int want_buf) {
  return test::libssh2_api_mock_instance.libssh2_session_last_error(session, errmsg, errmsg_len, want_buf);
}

int libssh2_session_last_errno(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_last_errno(session);
}

int libssh2_session_set_last_error(LIBSSH2_SESSION* session, int errcode, const char* errmsg) {
  return test::libssh2_api_mock_instance.libssh2_session_set_last_error(session, errcode, errmsg);
}

int libssh2_session_block_directions(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_block_directions(session);
}

int libssh2_session_flag(LIBSSH2_SESSION* session, int flag, int value) {
  return test::libssh2_api_mock_instance.libssh2_session_flag(session, flag, value);
}

const char* libssh2_session_banner_get(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_banner_get(session);
}

char* libssh2_userauth_list(LIBSSH2_SESSION* session, const char* username, unsigned int username_len) {
  return test::libssh2_api_mock_instance.libssh2_userauth_list(session, username, username_len);
}

int libssh2_userauth_authenticated(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_userauth_authenticated(session);
}

int libssh2_userauth_password_ex(LIBSSH2_SESSION* session, const char* username, unsigned int username_len, const char* password, unsigned int password_len, libssh2_passwd_changereq_func passwd_change_cb) {
  return test::libssh2_api_mock_instance.libssh2_userauth_password_ex(session, username, username_len, password, password_len, passwd_change_cb);
}

int libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION* session, const char* username, unsigned int username_len, const char* publickey, const char* privatekey, const char* passphrase) {
  return test::libssh2_api_mock_instance.libssh2_userauth_publickey_fromfile_ex(session, username, username_len, publickey, privatekey, passphrase);
}

int libssh2_userauth_publickey(LIBSSH2_SESSION* session, const char* username, const unsigned char* pubkeydata, size_t pubkeydata_len, libssh2_sign_callback_func sign_callback, void** abstract) {
  return test::libssh2_api_mock_instance.libssh2_userauth_publickey(session, username, pubkeydata, pubkeydata_len, sign_callback, abstract);
}

int libssh2_userauth_hostbased_fromfile_ex(LIBSSH2_SESSION* session, const char* username, unsigned int username_len, const char* publickey, const char* privatekey, const char* passphrase, const char* hostname, unsigned int hostname_len, const char* local_username, unsigned int local_username_len) {
  return test::libssh2_api_mock_instance.libssh2_userauth_hostbased_fromfile_ex(session, username, username_len, publickey, privatekey, passphrase, hostname, hostname_len, local_username, local_username_len);
}

int libssh2_userauth_publickey_frommemory(LIBSSH2_SESSION* session, const char* username, size_t username_len, const char* publickeyfiledata, size_t publickeyfiledata_len, const char* privatekeyfiledata, size_t privatekeyfiledata_len, const char* passphrase) {
  return test::libssh2_api_mock_instance.libssh2_userauth_publickey_frommemory(session, username, username_len, publickeyfiledata, publickeyfiledata_len, privatekeyfiledata, privatekeyfiledata_len, passphrase);
}

int libssh2_userauth_keyboard_interactive_ex(LIBSSH2_SESSION* session, const char* username, unsigned int username_len, libssh2_userauth_kbdint_response_func response_callback) {
  return test::libssh2_api_mock_instance.libssh2_userauth_keyboard_interactive_ex(session, username, username_len, response_callback);
}

int libssh2_poll(LIBSSH2_POLLFD* fds, unsigned int nfds, long timeout) {
  return test::libssh2_api_mock_instance.libssh2_poll(fds, nfds, timeout);
}

LIBSSH2_CHANNEL* libssh2_channel_open_ex(LIBSSH2_SESSION* session, const char* channel_type, unsigned int channel_type_len, unsigned int window_size, unsigned int packet_size, const char* message, unsigned int message_len) {
  return test::libssh2_api_mock_instance.libssh2_channel_open_ex(session, channel_type, channel_type_len, window_size, packet_size, message, message_len);
}

LIBSSH2_CHANNEL* libssh2_channel_direct_tcpip_ex(LIBSSH2_SESSION* session, const char* host, int port, const char* shost, int sport) {
  return test::libssh2_api_mock_instance.libssh2_channel_direct_tcpip_ex(session, host, port, shost, sport);
}

LIBSSH2_LISTENER* libssh2_channel_forward_listen_ex(LIBSSH2_SESSION* session, const char* host, int port, int* bound_port, int queue_maxsize) {
  return test::libssh2_api_mock_instance.libssh2_channel_forward_listen_ex(session, host, port, bound_port, queue_maxsize);
}

int libssh2_channel_forward_cancel(LIBSSH2_LISTENER* listener) {
  return test::libssh2_api_mock_instance.libssh2_channel_forward_cancel(listener);
}

LIBSSH2_CHANNEL* libssh2_channel_forward_accept(LIBSSH2_LISTENER* listener) {
  return test::libssh2_api_mock_instance.libssh2_channel_forward_accept(listener);
}

int libssh2_channel_setenv_ex(LIBSSH2_CHANNEL* channel, const char* varname, unsigned int varname_len, const char* value, unsigned int value_len) {
  return test::libssh2_api_mock_instance.libssh2_channel_setenv_ex(channel, varname, varname_len, value, value_len);
}

int libssh2_channel_request_auth_agent(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_request_auth_agent(channel);
}

int libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL* channel, const char* term, unsigned int term_len, const char* modes, unsigned int modes_len, int width, int height, int width_px, int height_px) {
  return test::libssh2_api_mock_instance.libssh2_channel_request_pty_ex(channel, term, term_len, modes, modes_len, width, height, width_px, height_px);
}

int libssh2_channel_request_pty_size_ex(LIBSSH2_CHANNEL* channel, int width, int height, int width_px, int height_px) {
  return test::libssh2_api_mock_instance.libssh2_channel_request_pty_size_ex(channel, width, height, width_px, height_px);
}

int libssh2_channel_x11_req_ex(LIBSSH2_CHANNEL* channel, int single_connection, const char* auth_proto, const char* auth_cookie, int screen_number) {
  return test::libssh2_api_mock_instance.libssh2_channel_x11_req_ex(channel, single_connection, auth_proto, auth_cookie, screen_number);
}

int libssh2_channel_process_startup(LIBSSH2_CHANNEL* channel, const char* request, unsigned int request_len, const char* message, unsigned int message_len) {
  return test::libssh2_api_mock_instance.libssh2_channel_process_startup(channel, request, request_len, message, message_len);
}

ssize_t libssh2_channel_read_ex(LIBSSH2_CHANNEL* channel, int stream_id, char* buf, size_t buflen) {
  return test::libssh2_api_mock_instance.libssh2_channel_read_ex(channel, stream_id, buf, buflen);
}

int libssh2_poll_channel_read(LIBSSH2_CHANNEL* channel, int extended) {
  return test::libssh2_api_mock_instance.libssh2_poll_channel_read(channel, extended);
}

unsigned long libssh2_channel_window_read_ex(LIBSSH2_CHANNEL* channel, unsigned long* read_avail, unsigned long* window_size_initial) {
  return test::libssh2_api_mock_instance.libssh2_channel_window_read_ex(channel, read_avail, window_size_initial);
}

int libssh2_channel_receive_window_adjust2(LIBSSH2_CHANNEL* channel, unsigned long adjustment, unsigned char force, unsigned int* storewindow) {
  return test::libssh2_api_mock_instance.libssh2_channel_receive_window_adjust2(channel, adjustment, force, storewindow);
}

ssize_t libssh2_channel_write_ex(LIBSSH2_CHANNEL* channel, int stream_id, const char* buf, size_t buflen) {
  return test::libssh2_api_mock_instance.libssh2_channel_write_ex(channel, stream_id, buf, buflen);
}

unsigned long libssh2_channel_window_write_ex(LIBSSH2_CHANNEL* channel, unsigned long* window_size_initial) {
  return test::libssh2_api_mock_instance.libssh2_channel_window_write_ex(channel, window_size_initial);
}

void libssh2_session_set_blocking(LIBSSH2_SESSION* session, int blocking) {
  return test::libssh2_api_mock_instance.libssh2_session_set_blocking(session, blocking);
}

int libssh2_session_get_blocking(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_get_blocking(session);
}

void libssh2_channel_set_blocking(LIBSSH2_CHANNEL* channel, int blocking) {
  return test::libssh2_api_mock_instance.libssh2_channel_set_blocking(channel, blocking);
}

void libssh2_session_set_timeout(LIBSSH2_SESSION* session, long timeout) {
  return test::libssh2_api_mock_instance.libssh2_session_set_timeout(session, timeout);
}

long libssh2_session_get_timeout(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_session_get_timeout(session);
}

int libssh2_channel_handle_extended_data2(LIBSSH2_CHANNEL* channel, int ignore_mode) {
  return test::libssh2_api_mock_instance.libssh2_channel_handle_extended_data2(channel, ignore_mode);
}

int libssh2_channel_flush_ex(LIBSSH2_CHANNEL* channel, int streamid) {
  return test::libssh2_api_mock_instance.libssh2_channel_flush_ex(channel, streamid);
}

int libssh2_channel_get_exit_status(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_get_exit_status(channel);
}

int libssh2_channel_get_exit_signal(LIBSSH2_CHANNEL* channel, char** exitsignal, size_t* exitsignal_len, char** errmsg, size_t* errmsg_len, char** langtag, size_t* langtag_len) {
  return test::libssh2_api_mock_instance.libssh2_channel_get_exit_signal(channel, exitsignal, exitsignal_len, errmsg, errmsg_len, langtag, langtag_len);
}

int libssh2_channel_send_eof(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_send_eof(channel);
}

int libssh2_channel_eof(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_eof(channel);
}

int libssh2_channel_wait_eof(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_wait_eof(channel);
}

int libssh2_channel_close(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_close(channel);
}

int libssh2_channel_wait_closed(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_wait_closed(channel);
}

int libssh2_channel_free(LIBSSH2_CHANNEL* channel) {
  return test::libssh2_api_mock_instance.libssh2_channel_free(channel);
}

LIBSSH2_CHANNEL* libssh2_scp_recv2(LIBSSH2_SESSION* session, const char* path, libssh2_struct_stat* sb) {
  return test::libssh2_api_mock_instance.libssh2_scp_recv2(session, path, sb);
}

LIBSSH2_CHANNEL* libssh2_scp_send_ex(LIBSSH2_SESSION* session, const char* path, int mode, size_t size, long mtime, long atime) {
  return test::libssh2_api_mock_instance.libssh2_scp_send_ex(session, path, mode, size, mtime, atime);
}

LIBSSH2_CHANNEL* libssh2_scp_send64(LIBSSH2_SESSION* session, const char* path, int mode, libssh2_int64_t size, time_t mtime, time_t atime) {
  return test::libssh2_api_mock_instance.libssh2_scp_send64(session, path, mode, size, mtime, atime);
}

int libssh2_base64_decode(LIBSSH2_SESSION* session, char** dest, unsigned int* dest_len, const char* src, unsigned int src_len) {
  return test::libssh2_api_mock_instance.libssh2_base64_decode(session, dest, dest_len, src, src_len);
}

const char* libssh2_version(int req_version_num) {
  return test::libssh2_api_mock_instance.libssh2_version(req_version_num);
}

LIBSSH2_KNOWNHOSTS* libssh2_knownhost_init(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_init(session);
}

int libssh2_knownhost_add(LIBSSH2_KNOWNHOSTS* hosts, const char* host, const char* salt, const char* key, size_t keylen, int typemask, struct libssh2_knownhost** store) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_add(hosts, host, salt, key, keylen, typemask, store);
}

int libssh2_knownhost_addc(LIBSSH2_KNOWNHOSTS* hosts, const char* host, const char* salt, const char* key, size_t keylen, const char* comment, size_t commentlen, int typemask, struct libssh2_knownhost** store) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_addc(hosts, host, salt, key, keylen, comment, commentlen, typemask, store);
}

int libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS* hosts, const char* host, const char* key, size_t keylen, int typemask, struct libssh2_knownhost** knownhost) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_check(hosts, host, key, keylen, typemask, knownhost);
}

int libssh2_knownhost_checkp(LIBSSH2_KNOWNHOSTS* hosts, const char* host, int port, const char* key, size_t keylen, int typemask, struct libssh2_knownhost** knownhost) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_checkp(hosts, host, port, key, keylen, typemask, knownhost);
}

int libssh2_knownhost_del(LIBSSH2_KNOWNHOSTS* hosts, struct libssh2_knownhost* entry) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_del(hosts, entry);
}

void libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS* hosts) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_free(hosts);
}

int libssh2_knownhost_readline(LIBSSH2_KNOWNHOSTS* hosts, const char* line, size_t len, int type) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_readline(hosts, line, len, type);
}

int libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS* hosts, const char* filename, int type) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_readfile(hosts, filename, type);
}

int libssh2_knownhost_writeline(LIBSSH2_KNOWNHOSTS* hosts, struct libssh2_knownhost* known, char* buffer, size_t buflen, size_t* outlen, int type) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_writeline(hosts, known, buffer, buflen, outlen, type);
}

int libssh2_knownhost_writefile(LIBSSH2_KNOWNHOSTS* hosts, const char* filename, int type) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_writefile(hosts, filename, type);
}

int libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS* hosts, struct libssh2_knownhost** store, struct libssh2_knownhost* prev) {
  return test::libssh2_api_mock_instance.libssh2_knownhost_get(hosts, store, prev);
}

LIBSSH2_AGENT* libssh2_agent_init(LIBSSH2_SESSION* session) {
  return test::libssh2_api_mock_instance.libssh2_agent_init(session);
}

int libssh2_agent_connect(LIBSSH2_AGENT* agent) {
  return test::libssh2_api_mock_instance.libssh2_agent_connect(agent);
}

int libssh2_agent_list_identities(LIBSSH2_AGENT* agent) {
  return test::libssh2_api_mock_instance.libssh2_agent_list_identities(agent);
}

int libssh2_agent_get_identity(LIBSSH2_AGENT* agent, struct libssh2_agent_publickey** store, struct libssh2_agent_publickey* prev) {
  return test::libssh2_api_mock_instance.libssh2_agent_get_identity(agent, store, prev);
}

int libssh2_agent_userauth(LIBSSH2_AGENT* agent, const char* username, struct libssh2_agent_publickey* identity) {
  return test::libssh2_api_mock_instance.libssh2_agent_userauth(agent, username, identity);
}

int libssh2_agent_disconnect(LIBSSH2_AGENT* agent) {
  return test::libssh2_api_mock_instance.libssh2_agent_disconnect(agent);
}

void libssh2_agent_free(LIBSSH2_AGENT* agent) {
  return test::libssh2_api_mock_instance.libssh2_agent_free(agent);
}

void libssh2_agent_set_identity_path(LIBSSH2_AGENT* agent, const char* path) {
  return test::libssh2_api_mock_instance.libssh2_agent_set_identity_path(agent, path);
}

const char* libssh2_agent_get_identity_path(LIBSSH2_AGENT* agent) {
  return test::libssh2_api_mock_instance.libssh2_agent_get_identity_path(agent);
}

void libssh2_keepalive_config(LIBSSH2_SESSION* session, int want_reply, unsigned interval) {
  return test::libssh2_api_mock_instance.libssh2_keepalive_config(session, want_reply, interval);
}

int libssh2_keepalive_send(LIBSSH2_SESSION* session, int* seconds_to_next) {
  return test::libssh2_api_mock_instance.libssh2_keepalive_send(session, seconds_to_next);
}

int libssh2_trace(LIBSSH2_SESSION* session, int bitmask) {
  return test::libssh2_api_mock_instance.libssh2_trace(session, bitmask);
}

int libssh2_trace_sethandler(LIBSSH2_SESSION* session, void* context, libssh2_trace_handler_func callback) {
  return test::libssh2_api_mock_instance.libssh2_trace_sethandler(session, context, callback);
}

} // namespace detail::libssh2_api
} // namespace async_ssh
