#ifndef ASYNC_SSH_HOSTKEY_HASH_TYPE_HPP
#define ASYNC_SSH_HOSTKEY_HASH_TYPE_HPP

#include <libssh2.h>

namespace async_ssh {

/// The hash types available for SSH hostkey fingerprints
enum class hostkey_hash_type {
  /// MD5
  md5 = LIBSSH2_HOSTKEY_HASH_MD5,

  /// SHA1
  sha1 = LIBSSH2_HOSTKEY_HASH_SHA1,

  /// SHA256
  sha256 = LIBSSH2_HOSTKEY_HASH_SHA256
};

} // namespace async_ssh

#endif // ASYNC_SSH_HOSTKEY_HASH_TYPE_HPP
