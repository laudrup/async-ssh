#ifndef ASYNC_SSH_DETAIL_WINCOMPAT_HPP
#define ASYNC_SSH_DETAIL_WINCOMPAT_HPP

#ifdef _WIN32

#include <sys/stat.h>

#ifndef S_IFMT
# error "S_IFMT required"
#endif // S_IFMT

#ifndef S_IFDIR
# define S_IFDIR 0040000 /* Directory. */
#endif // S_IFDIR

#ifndef S_IFCHR
# define	S_IFCHR	0020000	/* Character device. */
#endif // S_IFCHR

#ifndef S_IFBLK
# define	S_IFBLK	0060000	/* Block device. */
#endif // S_IFBLK

#ifndef S_IFREG
# define	S_IFREG	0100000	/* Regular file. */
#endif // S_IFREG

#ifndef S_IFIFO
# define	S_IFIFO	0010000	/* FIFO. */
#endif // S_IFIFO

#ifndef S_IFLNK
# define	S_IFLNK	0120000	/* Symbolic link. */
#endif // S_IFLNK

#ifndef S_IFSOCK
# define	S_IFSOCK	0140000	/* Socket. */
#endif // S_IFSOCK

#ifndef S_ISDIR
# define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif // S_ISDIR

#ifndef S_ISCHR
# define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif // S_ISCHR

#ifndef S_ISBLK
# define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#endif // S_ISBLK

#ifndef S_ISREG
# define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif // S_ISREG

#ifndef S_ISFIFO
# define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#endif // S_ISFIFO

#ifndef S_ISLNK
# define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#endif // S_ISLNK

#ifndef S_ISSOCK
# define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#endif // SS_ISSOCK

#endif // _WIN32

#endif // ASYNC_SSH_DETAIL_WINCOMPAT_HPP
