/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2004 James Yonan <jim@yonan.net>
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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "win32.h"
#include "status.h"
#include "sig.h"
#include "occ.h"
#include "openvpn.h"

#include "memdbg.h"

/* Handle signals */

struct signal_info siginfo_static; /* GLOBAL */

const char *
signal_description (int signum, const char *sigtext)
{
  if (sigtext)
    return sigtext;
  else
    {
      switch (signum)
	{
	case SIGUSR1:
	  return "sigusr1";
	case SIGUSR2:
	  return "sigusr2";
	case SIGHUP:
	  return "sighup";
	case SIGTERM:
	  return "sigterm";
	case SIGINT:
	  return "sigint";
	default:
	  return "unknown";
	}
    }
}

static void
signal_reset (struct signal_info *si)
{
  if (si)
    {
      si->signal_received = 0;
      si->signal_text = NULL;
      si->hard = false;
    }
}

void
print_signal (const struct signal_info *si, const char *title, int msglevel)
{
  if (si)
    {
      const char *hs = (si->hard ? "hard" : "soft");
      const char *type = (si->signal_text ? si->signal_text : "");
      const char *t = (title ? title : "process");

      switch (si->signal_received)
	{
	case SIGINT:
	  msg (msglevel, "SIGINT[%s,%s] received, %s exiting", hs, type, t);
	  break;
	case SIGTERM:
	  msg (msglevel, "SIGTERM[%s,%s] received, %s exiting", hs, type, t);
	  break;
	case SIGHUP:
	  msg (msglevel, "SIGHUP[%s,%s] received, %s restarting", hs, type, t);
	  break;
	case SIGUSR1:
	  msg (msglevel, "SIGUSR1[%s,%s] received, %s restarting", hs, type, t);
	  break;
	default:
	  msg (msglevel, "Unknown signal %d [%s,%s] received by %s", si->signal_received, hs, type, t);
	  break;
	}
    }
  else
    msg (msglevel, "Unknown signal received");
}

#ifdef HAVE_SIGNAL_H

/* normal signal handler, when we are in event loop */
static void
signal_handler (int signum)
{
  siginfo_static.signal_received = signum;
  siginfo_static.hard = true;
  signal (signum, signal_handler);
}

/* temporary signal handler, before we are fully initialized */
static void
signal_handler_exit (int signum)
{
  msg (M_FATAL | M_NOLOCK,
       "Signal %d (%s) received during initialization, exiting",
       signum, signal_description (signum, NULL));
}

#endif

void
pre_init_signal_catch (void)
{
#ifdef HAVE_SIGNAL_H
  /*
   * Special handling if signal arrives before
   * we are properly initialized.
   */
  signal (SIGINT, signal_handler_exit);
  signal (SIGTERM, signal_handler_exit);
  signal (SIGHUP, SIG_IGN);
  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);
  signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGNAL_H */
}

void
post_init_signal_catch (void)
{
#ifdef HAVE_SIGNAL_H
  /* catch signals */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGHUP, signal_handler);
  signal (SIGUSR1, signal_handler);
  signal (SIGUSR2, signal_handler);
#endif /* HAVE_SIGNAL_H */
}

/*
 * Print statistics.
 *
 * Triggered by SIGUSR2 or F2 on Windows.
 */
void
print_status (const struct context *c, struct status_output *so)
{
  struct gc_arena gc = gc_new ();

  status_reset (so);

  status_printf (so, PACKAGE_NAME " STATISTICS");
  status_printf (so, "Updated,%s", time_string (0, 0, false, &gc));
  status_printf (so, "TUN/TAP read bytes," counter_format, c->c2.tun_read_bytes);
  status_printf (so, "TUN/TAP write bytes," counter_format, c->c2.tun_write_bytes);
  status_printf (so, "TCP/UDP read bytes," counter_format, c->c2.link_read_bytes);
  status_printf (so, "TCP/UDP write bytes," counter_format, c->c2.link_write_bytes);
  status_printf (so, "Auth read bytes," counter_format, c->c2.link_read_bytes_auth);
#ifdef USE_LZO
  if (c->options.comp_lzo)
    lzo_print_stats (&c->c2.lzo_compwork, so);
#endif
#ifdef WIN32
  if (tuntap_defined (c->c1.tuntap))
    status_printf (so, "TAP-WIN32 driver status,\"%s\"",
	 tap_win32_getinfo (c->c1.tuntap, &gc));
#endif

  status_printf (so, "END");
  status_flush (so);
  gc_free (&gc);
}

/*
 * Handle the triggering and time-wait of explicit
 * exit notification.
 */

static void
process_explicit_exit_notification_init (struct context *c)
{
  msg (M_INFO, "SIGTERM received, sending exit notification to peer");
  event_timeout_init (&c->c2.explicit_exit_notification_interval, 1, 0);
  reset_coarse_timers (c);
  signal_reset (c->sig);
  halt_non_edge_triggered_signals ();
  c->c2.explicit_exit_notification_time_wait = now;
}

void
process_explicit_exit_notification_timer_wakeup (struct context *c)
{
  if (event_timeout_trigger (&c->c2.explicit_exit_notification_interval,
			     &c->c2.timeval,
			     ETT_DEFAULT))
    {
      ASSERT (c->c2.explicit_exit_notification_time_wait && c->options.explicit_exit_notification);
      if (now >= c->c2.explicit_exit_notification_time_wait + c->options.explicit_exit_notification)
	{
	  event_timeout_clear (&c->c2.explicit_exit_notification_interval);
	  c->sig->signal_received = SIGTERM;
	  c->sig->signal_text = "exit-with-notification";
	}
      else
	{
	  c->c2.occ_op = OCC_EXIT;
	}
    }
}

/*
 * Process signals
 */

void
remap_signal (struct context *c)
{
  if (c->sig->signal_received == SIGUSR1 && c->options.remap_sigusr1)
    c->sig->signal_received = c->options.remap_sigusr1;
}

static void
process_sigusr2 (const struct context *c)
{
  struct status_output *so = status_open (NULL, 0, M_INFO, 0);
  print_status (c, so);
  status_close (so);
  signal_reset (c->sig);
}

static bool
process_sigterm (struct context *c)
{
  bool ret = true;
  if (c->options.explicit_exit_notification
      && !c->c2.explicit_exit_notification_time_wait)
    {
      process_explicit_exit_notification_init (c);
      ret = false;
    }
  return ret;
}

bool
process_signal (struct context *c)
{
  bool ret = true;

  if (c->sig->signal_received == SIGTERM || c->sig->signal_received == SIGINT)
    {
      ret = process_sigterm (c);
    }
  else if (c->sig->signal_received == SIGUSR2)
    {
      process_sigusr2 (c);
      ret = false;
    }
  return ret;
}
