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

/*
 * This file is based on the TUN/TAP driver interface routines
 * from VTun by Maxim Krasnyansky <max_mk@yahoo.com>.
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "tun.h"
#include "fdmisc.h"
#include "error.h"
#include "buffer.h"
#include "common.h"
#include "misc.h"
#include "mtu.h"

#include "memdbg.h"

bool
is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
  ASSERT (match_type);
  if (!dev)
    return false;
  if (dev_type)
    return !strcmp (dev_type, match_type);
  else
    return !strncmp (dev, match_type, strlen (match_type));
}

const char *
dev_type_string(const char *dev, const char *dev_type)
{
  if (is_dev_type (dev, dev_type, "tun"))
    return "tun";
  else if (is_dev_type (dev, dev_type, "tap"))
    return "tap";
  else if (is_dev_type (dev, dev_type, "null"))
    return "null";
  else
    return "[unknown-dev-type]";
}

const char *
dev_component_in_dev_node (const char *dev_node)
{
  const char *ret;
  const int dirsep = '/';

  if (dev_node)
    {
      ret = strrchr (dev_node, dirsep);
      if (ret && *ret)
	++ret;
      else
	ret = dev_node;
      if (*ret)
	return ret;
    }
  return NULL;
}

/*
 * Called by the open_tun function of OSes to check if we
 * explicitly support IPv6.
 *
 * In this context, explicit means that the OS expects us to
 * do something special to the tun socket in order to support
 * IPv6, i.e. it is not transparent.
 *
 * ipv6_explicitly_supported should be set to false if we don't
 * have any explicit IPv6 code in the tun device handler.
 *
 * If ipv6_explicitly_supported is true, then we have explicit
 * OS-specific tun dev code for handling IPv6.  If so, tt->ipv6
 * is set according to the --tun-ipv6 command line option.
 */
static void
ipv6_support (bool ipv6, bool ipv6_explicitly_supported, struct tuntap* tt)
{
  tt->ipv6 = false;
  if (ipv6_explicitly_supported)
    tt->ipv6 = ipv6;
  else if (ipv6)
    msg (M_WARN, "NOTE: explicit support for IPv6 tun devices is not provided for this OS");
}

/* do ifconfig */
void
do_ifconfig (const char *dev, const char *dev_type,
	     const char *ifconfig_local, const char *ifconfig_remote,
	     int tun_mtu)
{
  if (ifconfig_local && ifconfig_remote)
    {
      char command_line[512];

      if (!is_dev_type (dev, dev_type, "tun"))
	msg (M_FATAL, "%s is not a tun device.  The --ifconfig option works only for tun devices.  You should use an --up script to ifconfig a tap device.", dev);

#if defined(TARGET_LINUX)

      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s %s pointopoint %s mtu %d",
			dev,
			ifconfig_local,
			ifconfig_remote,
			tun_mtu
			);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "Linux ifconfig failed", true);

#elif defined(TARGET_SOLARIS)

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			dev,
			ifconfig_local,
			ifconfig_remote,
			tun_mtu
			);
      msg (M_INFO, "%s", command_line);
      if (!system_check (command_line, "Solaris ifconfig failed", false))
	{
	  openvpn_snprintf (command_line, sizeof (command_line),
			    IFCONFIG_PATH " %s unplumb",
			    dev
			    );
	  msg (M_INFO, "%s", command_line);
	  system_check (command_line, "Solaris ifconfig unplumb failed", false);
	  msg (M_FATAL, "ifconfig failed");
	}

#elif defined(TARGET_OPENBSD)

      /*
       * OpenBSD tun devices appear to be persistent by default.  It seems in order
       * to make this work correctly, we need to delete the previous instance
       * (if it exists), and re-ifconfig.  Let me know if you know a better way.
       */

      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s delete",
			dev);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, NULL, false);
      msg (M_INFO, "NOTE: Tried to delete pre-existing tun instance -- No Problem if failure");


      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      openvpn_snprintf (command_line, sizeof (command_line),
		IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
		dev,
		ifconfig_local,
		ifconfig_remote,
		tun_mtu
		);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "OpenBSD ifconfig failed", true);

#elif defined(TARGET_NETBSD)

      openvpn_snprintf (command_line, sizeof (command_line),
	        IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
	        dev,
		ifconfig_local,
                ifconfig_remote,
                tun_mtu
                );
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "NetBSD ifconfig failed", true);

#elif defined(TARGET_DARWIN)

      /*
       * Darwin seems to exhibit similar behaviour to OpenBSD...
       */

      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s delete",
			dev);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, NULL, false);
      msg (M_INFO, "NOTE: Tried to delete pre-existing tun instance -- No Problem if failure");


      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			dev,
			ifconfig_local,
			ifconfig_remote,
			tun_mtu
			);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "Darwin ifconfig failed", true);

#elif defined(TARGET_FREEBSD)

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			dev,
			ifconfig_local,
			ifconfig_remote,
			tun_mtu
			);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "FreeBSD ifconfig failed", true);
#else
      msg (M_FATAL, "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.  Attempted ifconfig command was: '%s'", command_line);
#endif
    }
}

void
clear_tuntap (struct tuntap *tuntap)
{
#ifdef WIN32
  tuntap->hand = NULL;
#else
  tuntap->fd = -1;
#endif
#ifdef TARGET_SOLARIS
  tuntap->ip_fd = -1;
#endif
  tuntap->ipv6 = false;
  CLEAR (tuntap->actual);
}

static void
open_null (struct tuntap *tt)
{
  clear_tuntap (tt);
  strncpynt (tt->actual, "null", sizeof (tt->actual));
}

#ifndef WIN32
static void
open_tun_generic (const char *dev, const char *dev_node,
		  bool ipv6, bool ipv6_explicitly_supported, bool dynamic,
		  struct tuntap *tt)
{
  char tunname[256];

  char dynamic_name[256];
  bool dynamic_opened = false;

  clear_tuntap (tt);

  ipv6_support (ipv6, ipv6_explicitly_supported, tt);

  if (!strcmp(dev, "null"))
    {
      open_null (tt);
    }
  else
    {
      /*
       * --dev-node specified, so open an explicit device node
       */
      if (dev_node)
	{
	  openvpn_snprintf (tunname, sizeof (tunname), "%s", dev_node);
	}
      else
	{
	  /*
	   * dynamic open is indicated by --dev specified without
	   * explicit unit number.  Try opening /dev/[dev]n
	   * where n = [0, 255].
	   */
	  if (dynamic && !has_digit(dev))
	    {
	      int i;
	      for (i = 0; i < 256; ++i)
		{
		  openvpn_snprintf (tunname, sizeof (tunname),
				    "/dev/%s%d", dev, i);
		  openvpn_snprintf (dynamic_name, sizeof (dynamic_name),
				    "%s%d", dev, i);
		  if ((tt->fd = open (tunname, O_RDWR)) > 0)
		    {
		      dynamic_opened = true;
		      break;
		    }
		  msg (D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
		}
	      if (!dynamic_opened)
		msg (M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
	    }
	  /*
	   * explicit unit number specified
	   */
	  else
	    {
	      openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
	    }
	}

      if (!dynamic_opened)
	{
	  if ((tt->fd = open (tunname, O_RDWR)) < 0)
	    msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
	}

      set_nonblock (tt->fd);
      set_cloexec (tt->fd); /* don't pass fd to scripts */
      msg (M_INFO, "TUN/TAP device %s opened", tunname);

      /* tt->actual is passed to up and down scripts and used as the ifconfig dev name */
      strncpynt (tt->actual, (dynamic_opened ? dynamic_name : dev), sizeof (tt->actual));
    }
}

static void
close_tun_generic (struct tuntap *tt)
{
  if (tt->fd >= 0)
    close (tt->fd);
  clear_tuntap (tt);
}

#endif

#if defined(TARGET_LINUX)

#ifdef HAVE_LINUX_IF_TUN_H	/* New driver support */

#ifndef HAVE_LINUX_SOCKIOS_H
#error header file linux/sockios.h required
#endif

#if defined(HAVE_TUN_PI) && defined(HAVE_IPHDR) && defined(HAVE_IOVEC) && defined(ETH_P_IPV6) && defined(ETH_P_IP) && defined(HAVE_READV) && defined(HAVE_WRITEV)
#define LINUX_IPV6 1
/* #warning IPv6 ON */
#else
#define LINUX_IPV6 0
/* #warning IPv6 OFF */
#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  struct ifreq ifr;

  clear_tuntap (tt);

  /*
   * Set tt->ipv6 to true if
   * (a) we have the capability of supporting --tun-ipv6, and
   * (b) --tun-ipv6 was specified.
   */
  ipv6_support (ipv6, LINUX_IPV6, tt);

  /*
   * We handle --dev null specially, we do not open /dev/null for this.
   */
  if (!strcmp(dev, "null"))
    {
      open_null (tt);
    }
  else
    {
      /*
       * Process --dev-node
       */
      const char *node = dev_node;
      if (!node)
	node = "/dev/net/tun";
      if ((tt->fd = open (node, O_RDWR)) < 0)
	{
	  msg (M_WARN | M_ERRNO, "Note: Cannot open TUN/TAP dev %s", node);
	  goto linux_2_2_fallback;
	}

      /*
       * Process --tun-ipv6
       */
      CLEAR (ifr);
      if (!tt->ipv6)
	ifr.ifr_flags = IFF_NO_PI;

      /*
       * Figure out if tun or tap device
       */
      if (is_dev_type (dev, dev_type, "tun"))
	{
	  ifr.ifr_flags |= IFF_TUN;
	}
      else if (is_dev_type (dev, dev_type, "tap"))
	{
	  ifr.ifr_flags |= IFF_TAP;
	}
      else
	{
	  msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	       dev);
	}

      /*
       * Set an explicit name, if --dev is not tun or tap
       */
      if (strcmp(dev, "tun") && strcmp(dev, "tap"))
	strncpynt (ifr.ifr_name, dev, IFNAMSIZ);

      /*
       * Use special ioctl that configures tun/tap device with the parms
       * we set in ifr
       */
      if (ioctl (tt->fd, TUNSETIFF, (void *) &ifr) < 0)
	{
	  msg (M_WARN | M_ERRNO, "Note: Cannot ioctl TUNSETIFF %s", dev);
	  goto linux_2_2_fallback;
	}

      set_nonblock (tt->fd);
      set_cloexec (tt->fd);
      msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);
      strncpynt (tt->actual, ifr.ifr_name, sizeof (tt->actual));
    }
  return;

 linux_2_2_fallback:
  msg (M_INFO, "Note: Attempting fallback to kernel 2.2 TUN/TAP interface");
  close_tun_generic (tt);
  open_tun_generic (dev, dev_node, ipv6, false, true, tt);
}

#else

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_node, ipv6, false, true, tt);
}

#endif /* HAVE_LINUX_IF_TUN_H */

#ifdef TUNSETPERSIST

void
tuncfg (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, int persist_mode)
{
  struct tuntap tt;

  open_tun (dev, dev_type, dev_node, ipv6, &tt);
  if (ioctl (tt.fd, TUNSETPERSIST, persist_mode) < 0)
    msg (M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);
  close_tun (&tt);
  msg (M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#endif /* TUNSETPERSIST */

void
close_tun (struct tuntap *tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
#if LINUX_IPV6
  if (tt->ipv6)
    {
      struct tun_pi pi;
      struct iphdr *iph;
      struct iovec vect[2];
      int ret;

      iph = (struct iphdr *)buf;

      pi.flags = 0;

      if(iph->version == 6)
	pi.proto = htons(ETH_P_IPV6);
      else
	pi.proto = htons(ETH_P_IP);

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = writev(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
#endif
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
#if LINUX_IPV6
  if (tt->ipv6)
    {
      struct iovec vect[2];
      struct tun_pi pi;
      int ret;

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = readv(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
#endif
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_SOLARIS)

#ifndef TUNNEWPPA
#error I need the symbol TUNNEWPPA from net/if_tun.h
#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  int if_fd, muxid, ppa = -1;
  struct ifreq ifr;
  const char *ptr;
  const char *ip_node;
  const char *dev_tuntap_type;
  int link_type;
  bool is_tun;

  clear_tuntap (tt);

  ipv6_support (ipv6, false, tt);

  if (!strcmp(dev, "null"))
    {
      open_null (tt);
      return;
    }

  if (is_dev_type (dev, dev_type, "tun"))
    {
      ip_node = "/dev/udp";
      if (!dev_node)
	dev_node = "/dev/tun";
      dev_tuntap_type = "tun";
      link_type = I_PLINK;
      is_tun = true;
    }
  else if (is_dev_type (dev, dev_type, "tap"))
    {
      ip_node = "/dev/ip";
      if (!dev_node)
	dev_node = "/dev/tap";
      dev_tuntap_type = "tap";
      link_type = I_PLINK; /* was: I_LINK */
      is_tun = false;
    }
  else
    {
      msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	   dev);
    }
  
  /* get unit number */
  if (*dev)
    {
      ptr = dev;
      while (*ptr && !isdigit ((int) *ptr))
	ptr++;
      ppa = atoi (ptr);
    }

  if ((tt->ip_fd = open (ip_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", ip_node);

  if ((tt->fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", dev_node);

  /* Assign a new PPA and get its unit number. */
  if ((ppa = ioctl (tt->fd, TUNNEWPPA, ppa)) < 0)
    msg (M_ERR, "Can't assign new interface");

  if ((if_fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s (2)", dev_node);

  if (ioctl (if_fd, I_PUSH, "ip") < 0)
    msg (M_ERR, "Can't push IP module");

  /* Assign ppa according to the unit number returned by tun device */
  if (ioctl (if_fd, IF_UNITSEL, (char *) &ppa) < 0)
    msg (M_ERR, "Can't set PPA %d", ppa);

  if ((muxid = ioctl (tt->ip_fd, link_type, if_fd)) < 0)
    msg (M_ERR, "Can't link %s device to IP", dev_tuntap_type);

  close (if_fd);

  openvpn_snprintf (tt->actual, sizeof (tt->actual),
		    "%s%d", dev_tuntap_type, ppa);

  CLEAR (ifr);
  strncpynt (ifr.ifr_name, tt->actual, sizeof (ifr.ifr_name));
  ifr.ifr_ip_muxid = muxid;

  if (ioctl (tt->ip_fd, SIOCSIFMUXID, &ifr) < 0)
    {
      ioctl (tt->ip_fd, I_PUNLINK, muxid);
      msg (M_ERR, "Can't set multiplexor id");
    }

  set_nonblock (tt->fd);
  set_cloexec (tt->fd);
  set_cloexec (tt->ip_fd);

  msg (M_INFO, "TUN/TAP device %s opened", tt->actual);
}

/*
 * Close TUN device. 
 */
void
close_tun (struct tuntap* tt)
{
  if (tt->fd >= 0)
    {
      struct ifreq ifr;

      CLEAR (ifr);
      strncpynt (ifr.ifr_name, tt->actual, sizeof (ifr.ifr_name));

     if (ioctl (tt->ip_fd, SIOCGIFFLAGS, &ifr) < 0)
	msg (M_WARN | M_ERRNO, "Can't get iface flags");

      if (ioctl (tt->ip_fd, SIOCGIFMUXID, &ifr) < 0)
	msg (M_WARN | M_ERRNO, "Can't get multiplexor id");

      if (ioctl (tt->ip_fd, I_PUNLINK, ifr.ifr_ip_muxid) < 0)
	msg (M_WARN | M_ERRNO, "Can't unlink interface");

      close (tt->ip_fd);
      close (tt->fd);
    }
  clear_tuntap (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  struct strbuf sbuf;
  sbuf.len = len;
  sbuf.buf = (char *)buf;
  return putmsg (tt->fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  struct strbuf sbuf;
  int f = 0;

  sbuf.maxlen = len;
  sbuf.buf = (char *)buf;
  return getmsg (tt->fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
}

#elif defined(TARGET_OPENBSD)

#if !defined(HAVE_READV) || !defined(HAVE_WRITEV)
#error openbsd build requires readv & writev library functions
#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_node, ipv6, false, true, tt);
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

static inline int
openbsd_modify_read_write_return (int len)
{
 if (len > 0)
    return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  u_int32_t type = htonl (AF_INET);
  struct iovec iv[2];

  iv[0].iov_base = &type;
  iv[0].iov_len = sizeof (type);
  iv[1].iov_base = buf;
  iv[1].iov_len = len;

  return openbsd_modify_read_write_return (writev (tt->fd, iv, 2));
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  u_int32_t type;
  struct iovec iv[2];

  iv[0].iov_base = &type;
  iv[0].iov_len = sizeof (type);
  iv[1].iov_base = buf;
  iv[1].iov_len = len;

  return openbsd_modify_read_write_return (readv (tt->fd, iv, 2));
}

#elif defined(TARGET_FREEBSD)

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_node, ipv6, false, true, tt);

  if (tt->fd >= 0)
    {
      int i = 0;

      /* Disable extended modes */
      ioctl (tt->fd, TUNSLMODE, &i);
      ioctl (tt->fd, TUNSIFHEAD, &i);
    }
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return read (tt->fd, buf, len);
}

#elif defined(WIN32)

int
tun_read_queue (struct tuntap *tt, int maxsize)
{
  if (tt->reads.iostate == IOSTATE_INITIAL)
    {
      DWORD len;
      BOOL status;
      int err;

      /* reset buf to its initial state */
      tt->reads.buf = tt->reads.buf_init;

      len = maxsize ? maxsize : BLEN (&tt->reads.buf);
      ASSERT (len <= BLEN (&tt->reads.buf));

      /* the overlapped read will signal this event on I/O completion */
      ASSERT (ResetEvent (tt->reads.overlapped.hEvent));

      status = ReadFile(
		      tt->hand,
		      BPTR (&tt->reads.buf),
		      len,
		      &tt->reads.size,
		      &tt->reads.overlapped
		      );

      if (status) /* operation completed immediately? */
	{
	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (tt->reads.overlapped.hEvent));

	  tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	  tt->reads.status = 0;

	  msg (D_WIN32_IO, "WIN32 I/O: TAP Read immediate return [%d,%d]",
	       (int) len,
	       (int) tt->reads.size);	       
	}
      else
	{
	  err = GetLastError (); 
	  if (err == ERROR_IO_PENDING) /* operation queued? */
	    {
	      tt->reads.iostate = IOSTATE_QUEUED;
	      tt->reads.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Read queued [%d]",
		   (int) len);
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (tt->reads.overlapped.hEvent));
	      tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	      tt->reads.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Read error [%d]: %s",
		   (int) len,
		   strerror_win32 (status));
	    }
	}
    }
  return tt->reads.iostate;
}

int
tun_write_queue (struct tuntap *tt, struct buffer *buf)
{
  if (tt->writes.iostate == IOSTATE_INITIAL)
    {
      BOOL status;
      int err;
 
      /* make a private copy of buf */
      tt->writes.buf = tt->writes.buf_init;
      tt->writes.buf.len = 0;
      ASSERT (buf_copy (&tt->writes.buf, buf));

      /* the overlapped write will signal this event on I/O completion */
      ASSERT (ResetEvent (tt->writes.overlapped.hEvent));

      status = WriteFile(
			tt->hand,
			BPTR (&tt->writes.buf),
			BLEN (&tt->writes.buf),
			&tt->writes.size,
			&tt->writes.overlapped
			);

      if (status) /* operation completed immediately? */
	{
	  tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (tt->writes.overlapped.hEvent));

	  tt->writes.status = 0;

	  msg (D_WIN32_IO, "WIN32 I/O: TAP Write immediate return [%d,%d]",
	       BLEN (&tt->writes.buf),
	       (int) tt->writes.size);	       
	}
      else
	{
	  err = GetLastError (); 
	  if (err == ERROR_IO_PENDING) /* operation queued? */
	    {
	      tt->writes.iostate = IOSTATE_QUEUED;
	      tt->writes.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Write queued [%d]",
		   BLEN (&tt->writes.buf));
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (tt->writes.overlapped.hEvent));
	      tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
	      tt->writes.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Write error [%d]: %s",
		   BLEN (&tt->writes.buf),
		   strerror_win32 (err));
	    }
	}
    }
  return tt->writes.iostate;
}

int
tun_finalize (
	      HANDLE h,
	      struct overlapped_io *io,
	      struct buffer *buf)
{
  int ret = -1;
  BOOL status;

  switch (io->iostate)
    {
    case IOSTATE_QUEUED:
      status = GetOverlappedResult(
				   h,
				   &io->overlapped,
				   &io->size,
				   FALSE
				   );
      if (status)
	{
	  /* successful return for a queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  ASSERT (ResetEvent (io->overlapped.hEvent));
	  msg (D_WIN32_IO, "WIN32 I/O: TAP Completion success [%d]", ret);
	}
      else
	{
	  /* error during a queued operation */
	  ret = -1;
	  if (GetLastError() != ERROR_IO_INCOMPLETE)
	    {
	      /* if no error (i.e. just not finished yet), then DON'T execute this code */
	      io->iostate = IOSTATE_INITIAL;
	      ASSERT (ResetEvent (io->overlapped.hEvent));
	      msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion error");
	    }
	}
      break;

    case IOSTATE_IMMEDIATE_RETURN:
      ASSERT (ResetEvent (io->overlapped.hEvent));
      if (io->status)
	{
	  /* error return for a non-queued operation */
	  SetLastError (io->status);
	  ret = -1;
	  msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion non-queued error");
	}
      else
	{
	  /* successful return for a non-queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  msg (D_WIN32_IO, "WIN32 I/O: TAP Completion non-queued success [%d]", ret);
	}
      break;

    case IOSTATE_INITIAL: /* were we called without proper queueing? */
      SetLastError (ERROR_INVALID_FUNCTION);
      ret = -1;
      msg (D_WIN32_IO, "WIN32 I/O: TAP Completion BAD STATE");
      break;

    default:
      ASSERT (0);
    }

  if (buf)
    buf->len = ret;
  return ret;
}

static bool
is_tap_win32_dev (const char* guid)
{
  HKEY netcard_key;
  LONG status;
  DWORD len;
  int i = 0;

  status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			NETCARD_REG_KEY_2000,
			0,
			KEY_READ,
			&netcard_key);

  if (status != ERROR_SUCCESS)
    msg (M_FATAL, "Error opening registry key: %s", NETCARD_REG_KEY_2000);

  while (true)
    {
      char enum_name[256];
      char unit_string[256];
      HKEY unit_key;
      char component_id_string[] = "ComponentId";
      char component_id[256];
      char net_cfg_instance_id_string[] = "NetCfgInstanceId";
      char net_cfg_instance_id[256];
      DWORD data_type;

      len = sizeof (enum_name);
      status = RegEnumKeyEx(
			    netcard_key,
			    i,
			    enum_name,
			    &len,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
      if (status == ERROR_NO_MORE_ITEMS)
	break;
      else if (status != ERROR_SUCCESS)
	msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
	     NETCARD_REG_KEY_2000);

      snprintf (unit_string, sizeof(unit_string), "%s\\%s",
		NETCARD_REG_KEY_2000, enum_name);

      status = RegOpenKeyEx(
			    HKEY_LOCAL_MACHINE,
			    unit_string,
			    0,
			    KEY_READ,
			    &unit_key);

      if (status != ERROR_SUCCESS)
	msg (D_REGISTRY, "Error opening registry key: %s", unit_string);
      else
	{
	  len = sizeof (component_id);
	  status = RegQueryValueEx(
				   unit_key,
				   component_id_string,
				   NULL,
				   &data_type,
				   component_id,
				   &len);

	  if (status != ERROR_SUCCESS || data_type != REG_SZ)
	    msg (D_REGISTRY, "Error opening registry key: %s\\%s",
		 unit_string, component_id_string);
	  else
	    {	      
	      len = sizeof (net_cfg_instance_id);
	      status = RegQueryValueEx(
				       unit_key,
				       net_cfg_instance_id_string,
				       NULL,
				       &data_type,
				       net_cfg_instance_id,
				       &len);

	      if (status == ERROR_SUCCESS && data_type == REG_SZ)
		{
		  msg (D_REGISTRY, "cid=%s netcfg=%s guid=%s",
		       component_id, net_cfg_instance_id, guid);
		  if (!strcmp (component_id, "tap")
		      && !strcmp (net_cfg_instance_id, guid))
		    {
		      RegCloseKey (unit_key);
		      RegCloseKey (netcard_key);
		      return true;
		    }
		}
	    }
	  RegCloseKey (unit_key);
	}
      ++i;
    }

  RegCloseKey (netcard_key);
  return false;
}


/* set name to NULL to enumerate all TAP devices */
static const char *
get_device_guid (const char *name)
{
# define REG_CONTROL_NET "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
  struct buffer out = alloc_buf_gc (256);
  LONG status;
  HKEY control_net_key;
  DWORD len;
  int i = 0;
  int n = 0;

  if (!name)
    msg (M_INFO, "Available TAP-WIN32 devices:");

  status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			REG_CONTROL_NET,
			0,
			KEY_READ,
			&control_net_key);

  if (status != ERROR_SUCCESS)
    msg (M_FATAL, "Error opening registry key: %s", REG_CONTROL_NET);

  while (true)
    {
      char enum_name[256];
      char connection_string[256];
      HKEY connection_key;
      char name_data[256];
      DWORD name_type;
      const char name_string[] = "Name";

      len = sizeof (enum_name);
      status = RegEnumKeyEx(
			    control_net_key,
			    i,
			    enum_name,
			    &len,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
      if (status == ERROR_NO_MORE_ITEMS)
	break;
      else if (status != ERROR_SUCCESS)
	msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
	     REG_CONTROL_NET);

      snprintf (connection_string, sizeof(connection_string),
		"%s\\%s\\Connection",
		REG_CONTROL_NET, enum_name);

      status = RegOpenKeyEx(
			    HKEY_LOCAL_MACHINE,
			    connection_string,
			    0,
			    KEY_READ,
			    &connection_key);

      if (status != ERROR_SUCCESS)
	msg (D_REGISTRY, "Error opening registry key: %s", connection_string);
      else
	{
	  len = sizeof (name_data);
	  status = RegQueryValueEx(
				   connection_key,
				   name_string,
				   NULL,
				   &name_type,
				   name_data,
				   &len);

	  if (status != ERROR_SUCCESS || name_type != REG_SZ)
	    msg (D_REGISTRY, "Error opening registry key: %s\\%s\\%s",
		 REG_CONTROL_NET, connection_string, name_string);
	  else
	    {
	      
	      if (is_tap_win32_dev (enum_name))
		{
		  if (name == NULL)
		    {
		      ++n;
		      msg (M_INFO, "[%d] '%s'", n, name_data);
		    }
		  else if (!strcmp (name_data, name))
		    {
		      buf_printf (&out, "%s", enum_name);
		      RegCloseKey (connection_key);
		      RegCloseKey (control_net_key);
		      return BSTR (&out);
		    }
		}
	    }

	  RegCloseKey (connection_key);
	}
      ++i;
    }

  RegCloseKey (control_net_key);
  if (name)
    msg (M_FATAL, "TAP device '%s' not found -- run with --show-adapters to show a list of TAP-WIN32 adapters on this system", name);
  return NULL;
}

void
show_tap_win32_adapters (void)
{
  get_device_guid (NULL);
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  char device_path[256];
  const char *device_guid = NULL;
  DWORD len;

  clear_tuntap (tt);

  ipv6_support (ipv6, false, tt);

  if (!strcmp(dev, "null"))
    {
      open_null (tt);
      return;
    }
  else if (is_dev_type (dev, dev_type, "tap"))
    {
      ;
    }
  else
    {
      msg (M_FATAL, "Unknown virtual device type: '%s' -- Currently only TAP virtual network devices are supported under Windows, so you should run with --dev tap --dev-node <your TAP-WIN32 adapter name> -- or run with --show-adapters to show a list of TAP-WIN32 adapters on this system", dev);
    }

  /*
   * Lookup the device name in the registry, using the --dev-node high level name.
   */
  if (!dev_node)
    {
      msg (M_FATAL, "--dev-node must be specified with the name of the TAP device as it appears in the network control panel or ipconfig command -- or run with --show-adapters to show a list of TAP-WIN32 adapters on this system");
    }
  else
    {
      /* translate high-level device name into a GUID using the registry */
      device_guid = get_device_guid (dev_node);
    }

  /*
   * Open Windows TAP device
   */
  snprintf (device_path, sizeof(device_path), "%s%s%s",
	    USERMODEDEVICEDIR,
	    device_guid,
	    TAPSUFFIX);

  tt->hand = CreateFile (
			 device_path,
			 GENERIC_READ | GENERIC_WRITE,
			 0, // was: FILE_SHARE_READ
			 0,
			 OPEN_EXISTING,
			 FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			 0
			 );

  if (tt->hand == INVALID_HANDLE_VALUE)
    msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);

  if (!DeviceIoControl (tt->hand, TAP_IOCTL_GET_MAC,
			tt->mac, sizeof (tt->mac),
			tt->mac, sizeof (tt->mac), &len, 0))
    msg (M_ERR, "DeviceIoControl TAP_IOCTL_GET_MAC failed");

  if (!DeviceIoControl (tt->hand, TAP_IOCTL_GET_LASTMAC,
			tt->next_mac, sizeof (tt->next_mac),
			tt->next_mac, sizeof (tt->next_mac), &len, 0))
    msg (M_ERR, "DeviceIoControl TAP_IOCTL_GET_LASTMAC failed");

  msg (M_INFO, "TAP-WIN32 device [%s] opened: %s", dev_node, device_path);

  /* tt->actual is passed to up and down scripts and used as the ifconfig dev name */
  strncpynt (tt->actual, device_path, sizeof (tt->actual));
}

void
tun_frame_init (struct frame *frame, struct tuntap *tt)
{
  overlapped_io_init (&tt->reads, frame, FALSE, true);
  overlapped_io_init (&tt->writes, frame, TRUE, true);
}

void
close_tun (struct tuntap *tt)
{
  overlapped_io_close (&tt->reads);
  overlapped_io_close (&tt->writes);
  if (tt->hand != NULL)
    {
      if (!CloseHandle (tt->hand))
	msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on TAP-Win32 device");
    }
  clear_tuntap (tt);
}

#else /* generic */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_node, ipv6, false, true, tt);
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return read (tt->fd, buf, len);
}

#endif
