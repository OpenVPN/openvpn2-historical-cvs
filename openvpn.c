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

#include "init.h"
#include "forward.h"
#include "multi.h"

#include "memdbg.h"

#include "forward-inline.h"

#define P2P_CHECK_SIG() EVENT_LOOP_CHECK_SIGNAL (c, process_signal_p2p, c);

static bool
process_signal_p2p (struct context *c)
{
  remap_signal (c);
  return process_signal (c);
}

static int
tunnel_point_to_point_event_loop (void *arg)
{
  struct context *c = (struct context *) arg;
  int ret = WT_EVENT_LOOP_NORMAL;

  while (true)
    {
      perf_push (PERF_EVENT_LOOP);

      /* process timers, TLS, etc. */
      pre_select (c);
      P2P_CHECK_SIG();

      /* set up and do the I/O wait */
      io_wait (c, p2p_iow_flags (c));
      P2P_CHECK_SIG();

      /* break from this event loop? */
      if (is_work_thread_break (c))
	{
	  ret = WT_EVENT_LOOP_BREAK;
	  perf_pop ();
	  break;
	}

      /* timeout? */
      if (c->c2.event_set_status == ES_TIMEOUT)
	{
	  perf_pop ();
	  continue;
	}

      /* process the I/O which triggered select */
      process_io (c);
      P2P_CHECK_SIG();

      perf_pop ();
    }
  return ret;
}

static void
tunnel_point_to_point (struct context *c)
{
  context_clear_2 (c);

  /* set point-to-point mode */
  c->mode = CM_P2P;

  /* initialize tunnel instance */
  init_instance (c, c->es, CC_HARD_USR1_TO_HUP);
  if (IS_SIG (c))
    return;

  init_management_callback_p2p (c);
  enable_work_thread (c, c, tunnel_point_to_point_event_loop);

  /* main event loop */
  tunnel_point_to_point_event_loop ((void *)c);

  disable_work_thread (c);
  uninit_management_callback ();

  /* tear down tunnel instance (unless --persist-tun) */
  close_instance (c);
}

#undef PROCESS_SIGNAL_P2P

int
main (int argc, char *argv[])
{
  struct context c;

  CLEAR (c);

  /* signify first time for components which can
     only be initialized once per program instantiation. */
  c.first_time = true;

  /* initialize program-wide statics */
  if (init_static ())
    {
      /*
       * This loop is initially executed on startup and then
       * once per SIGHUP.
       */
      do
	{
	  /* zero context struct but leave first_time member alone */
	  context_clear_all_except_first_time (&c);

	  /* static signal info object */
	  CLEAR (siginfo_static);
	  c.sig = &siginfo_static;

	  /* initialize garbage collector scoped to context object */
	  gc_init (&c.gc);

	  /* initialize environmental variable store */
	  c.es = env_set_create (&c.gc);

#ifdef ENABLE_MANAGEMENT
	  /* initialize management subsystem */
	  init_management (&c);
#endif

	  /* initialize options to default state */
	  init_options (&c.options);

	  /* parse command line options, and read configuration file */
	  parse_argv (&c.options, argc, argv, M_USAGE, OPT_P_DEFAULT, NULL, c.es);

	  /* init verbosity and mute levels */
	  init_verb_mute (&c, IVM_LEVEL_1);

	  /* set dev options */
	  init_options_dev (&c.options);

	  /* openssl print info? */
	  if (print_openssl_info (&c.options))
	    break;

	  /* --genkey mode? */
	  if (do_genkey (&c.options))
	    break;

	  /* tun/tap persist command? */
	  if (do_persist_tuntap (&c.options))
	    break;

	  /* sanity check on options */
	  options_postprocess (&c.options, c.first_time);

	  /* show all option settings */
	  show_settings (&c.options);

	  /* print version number */
	  msg (M_INFO, "%s", title_string);

	  /* misc stuff */
	  pre_setup (&c.options);

	  /* test crypto? */
	  if (do_test_crypto (&c.options))
	    break;
	  
#ifdef ENABLE_MANAGEMENT
	  /* open management subsystem */
	  if (!open_management (&c))
	    break;
#endif
	  
	  /* set certain options as environmental variables */
	  setenv_settings (c.es, &c.options);

	  /* finish context init */
	  context_init_1 (&c);

	  do
	    {
	      /* run tunnel depending on mode */
	      switch (c.options.mode)
		{
		case MODE_POINT_TO_POINT:
		  tunnel_point_to_point (&c);
		  break;
#if P2MP_SERVER
		case MODE_SERVER:
		  tunnel_server (&c);
		  break;
#endif
		default:
		  ASSERT (0);
		}

	      /* indicates first iteration -- has program-wide scope */
	      c.first_time = false;

	      /* any signals received? */
	      if (IS_SIG (&c))
		print_signal (c.sig, NULL, M_INFO);

	      /* pass restart status to management subsystem */
	      signal_restart_status (c.sig);
	    }
	  while (c.sig->signal_received == SIGUSR1);

	  uninit_options (&c.options);
	  gc_reset (&c.gc);
	}
      while (c.sig->signal_received == SIGHUP);
    }

  context_gc_free (&c);

#ifdef ENABLE_MANAGEMENT
  /* close management interface */
  close_management ();
#endif

  /* uninitialize program-wide statics */
  uninit_static ();

  openvpn_exit (OPENVPN_EXIT_STATUS_GOOD);  /* exit point */
  return 0;			            /* NOTREACHED */
}
