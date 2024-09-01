find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBSSH2 QUIET "libssh2")

find_path(LIBSSH2_INCLUDE_DIR
  NAMES
  libssh2.h
  HINTS
  ${PC_LIBSSH2_INCLUDE_DIRS}
  ${Libssh2_ROOT}/include
)
find_library(LIBSSH2_LIBRARY
  NAMES
  ssh2
  libssh2
  HINTS
  ${PC_LIBSSH2_LIBRARY_DIRS}
  ${Libssh2_ROOT}/lib
)

if (LIBSSH2_INCLUDE_DIR)
  file(STRINGS "${LIBSSH2_INCLUDE_DIR}/libssh2.h" version-file
    REGEX "#define[ \t]LIBSSH2_VERSION_(MAJOR|MINOR|PATCH).*")
  if (NOT version-file)
    message(AUTHOR_WARNING "LIBSSH2_INCLUDE_DIR found, but cannot parse library version")
  else()
    list(GET version-file 0 major-line)
    list(GET version-file 1 minor-line)
    list(GET version-file 2 patch-line)
    string(REGEX REPLACE "^#define[ \t]+LIBSSH2_VERSION_MAJOR[ \t]+([0-9]+)$" "\\1" LIBSSH2_VERSION_MAJOR ${major-line})
    string(REGEX REPLACE "^#define[ \t]+LIBSSH2_VERSION_MINOR[ \t]+([0-9]+)$" "\\1" LIBSSH2_VERSION_MINOR ${minor-line})
    string(REGEX REPLACE "^#define[ \t]+LIBSSH2_VERSION_PATCH[ \t]+([0-9]+)$" "\\1" LIBSSH2_VERSION_PATCH ${patch-line})
    set(LIBSSH2_VERSION_STRING "${LIBSSH2_VERSION_MAJOR}.${LIBSSH2_VERSION_MINOR}.${LIBSSH2_VERSION_PATCH}")
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  Libssh2
  REQUIRED_VARS LIBSSH2_INCLUDE_DIR LIBSSH2_LIBRARY
  VERSION_VAR LIBSSH2_VERSION_STRING
)

if(LIBSSH2_FOUND)
  mark_as_advanced(LIBSSH2_INCLUDE_DIR LIBSSH2_LIBRARY)
endif()

if(LIBSSH2_FOUND AND NOT TARGET libssh2::libssh2)
  add_library(libssh2::libssh2 UNKNOWN IMPORTED)
  set_property(TARGET libssh2::libssh2 PROPERTY IMPORTED_LOCATION ${LIBSSH2_LIBRARY})
  target_include_directories(libssh2::libssh2 INTERFACE ${LIBSSH2_INCLUDE_DIR})
  if(WIN32)
    target_link_libraries(libssh2::libssh2 INTERFACE wsock32)
  endif()
endif()
