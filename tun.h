/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "openvpn-win32.h"

/*
 * Define a TUN/TAP dev.
 */


struct tuntap
{
#ifdef WIN32
  /* these macros are called in the context of the openvpn() function */
# define TUNTAP_SET(tt, set) { if (tt->hand != NULL)   wait_add     (&event_wait, tt->set.overlapped.hEvent); }
# define TUNTAP_ISSET(tt, set)    (tt->hand != NULL && wait_trigger (&event_wait, tt->set.overlapped.hEvent))
# define TUNTAP_SETMAXFD(tt)
# define TUNTAP_READ_STAT(tt)  (tt->hand != NULL ? overlapped_io_state_ascii (&tt->reads,  "tr") : "trX")
# define TUNTAP_WRITE_STAT(tt) (tt->hand != NULL ? overlapped_io_state_ascii (&tt->writes, "tw") : "twX")
  HANDLE hand;
  struct overlapped_io reads;
  struct overlapped_io writes;
#else
  /* these macros are called in the context of the openvpn() function */
# define TUNTAP_SET(tt, set)   { if (tt->fd >= 0)   FD_SET   (tt->fd, &event_wait.set);    }
# define TUNTAP_ISSET(tt, set)      (tt->fd >= 0 && FD_ISSET (tt->fd, &event_wait.set))
# define TUNTAP_SETMAXFD(tt)   { if (tt->fd >= 0)   wait_update_maxfd (&event_wait, tt->fd); }
# define TUNTAP_READ_STAT(tt)  (TUNTAP_ISSET (tt, reads) ?  "TR" : "tr")
# define TUNTAP_WRITE_STAT(tt) (TUNTAP_ISSET (tt, writes) ? "TW" : "tw")
  int fd;   /* file descriptor for TUN/TAP dev */
#endif
#ifdef TARGET_SOLARIS
  int ip_fd;
#endif
  bool ipv6;
  char actual[256]; /* actual name of TUN/TAP dev, usually including unit number */
};

void clear_tuntap (struct tuntap *tuntap);

void open_tun (const char *dev, const char *dev_type, const char *dev_node,
	  bool ipv6, struct tuntap *tt);
void close_tun (struct tuntap *tt);

int write_tun (struct tuntap* tt, uint8_t *buf, int len);
int read_tun (struct tuntap* tt, uint8_t *buf, int len);

void tuncfg (const char *dev, const char *dev_type, const char *dev_node,
	  bool ipv6, int persist_mode);

void do_ifconfig (const char *dev, const char *dev_type,
		  const char *ifconfig_local, const char *ifconfig_remote,
		  int tun_mtu);

const char *dev_component_in_dev_node (const char *dev_node);

bool is_dev_type (const char *dev, const char *dev_type, const char *match_type);
const char *dev_type_string (const char *dev, const char *dev_type);

/*
 * Inline functions
 */

static inline bool
tuntap_defined (const struct tuntap* tt)
{
#ifdef WIN32
  return tt->hand != NULL;
#else
  return tt->fd >= 0;
#endif
}

static inline void
tun_adjust_frame_parameters (struct frame* frame, int size)
{
  frame_add_to_extra_tun (frame, size);
}

/*
 * Should ifconfig be called before or after
 * tun dev open?
 */

#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_AFTER_TUN_OPEN  1
#define IFCONFIG_DEFAULT         1

static inline int
ifconfig_order(void)
{
#if defined(TARGET_LINUX)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_SOLARIS)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_OPENBSD)
  return IFCONFIG_BEFORE_TUN_OPEN;
#elif defined(TARGET_DARWIN)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_NETBSD)
  return IFCONFIG_AFTER_TUN_OPEN;
#else
  return IFCONFIG_DEFAULT;
#endif
}
