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

static void
tunnel_point_to_point (struct context *c)
{
  c->mode = CM_P2P;
  context_clear_2 (c);

  /* initialize tunnel instance */
  init_instance (c);
  if (IS_SIG (c))
    return;

  /* main event loop */
  while (true)
    {
      /* process timers, TLS, etc. */
      pre_select (c);
      if (IS_SIG (c))
	break;

      /* set up and do the select() */
      single_select (c);

      /* process signals */
      if (IS_SIG (c))
	{
	  if (c->sig->signal_received == SIGUSR2)
	    {
	      print_status (c);
	      c->sig->signal_received = 0;
	      continue;
	    }
	  break;
	}

      /* timeout? */
      if (!c->c2.select_status)
	continue;

      /* process the I/O which triggered select */
      process_io (c);
      if (IS_SIG (c))
	break;
    }

  /* tear down tunnel instance (unless --persist-tun) */
  close_instance (c);
  c->first_time = false;
}

#if P2MP

/*
 * Check for signals -- to be used
 * in the context of the
 * tunnel_multiclient_udp_server function. 
 */
#define TNUS_SIG() \
  if (IS_SIG (top)) \
  { \
    if (top->sig->signal_received == SIGUSR2) \
      { \
        multi_print_status (&multi, top); \
        top->sig->signal_received = 0; \
        continue; \
      } \
    break; \
  }

static void
tunnel_nonforking_udp_server (struct context *top)
{
  struct multi_context multi;

  ASSERT (top->options.proto == PROTO_UDPv4);
  ASSERT (top->options.mode == MODE_NONFORKING_UDP_SERVER);

#ifdef USE_PTHREAD
  top->options.tls_thread = false;
#endif

  multi_init (&multi, top);
  context_clear_2 (top);

  /* initialize tunnel instance */
  init_instance (top);
  if (IS_SIG (top))
    return;

  /* per-packet event loop */
  while (true)
    {
      /* set up and do the select() */
      multi_select (&multi, top);
      TNUS_SIG ();

      /* timeout? */
      if (!top->c2.select_status)
	{
	  multi_process_timeout (&multi, top);
	  continue;
	}

      /* process the I/O which triggered select */
      multi_process_io (&multi, top);
      TNUS_SIG ();
    }

  /* tear down tunnel instance (unless --persist-tun) */
  close_instance (top);
  multi_uninit (&multi);
  top->first_time = false;
}

#endif

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

	  /* initialize garbage collector scoped to context object */
	  gc_init (&c.gc);

	  /* static signal info object */
	  c.sig = &siginfo_static;

	  /* initialize options to default state */
	  init_options (&c.options);

	  /* parse command line options, and read configuration file */
	  parse_argv (&c.options, argc, argv);

	  /* init verbosity and mute levels */
	  init_verb_mute (&c.options);

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

	  /* test crypto? */
	  if (do_test_crypto (&c.options))
	    break;

	  /* misc stuff */
	  pre_setup (&c.options);

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
#if P2MP
		case MODE_NONFORKING_UDP_SERVER:
		  tunnel_nonforking_udp_server (&c);
		  break;
#endif
		default:
		  ASSERT (0);
		}

	      /* any signals received? */
	      if (IS_SIG (&c))
		print_signal (c.sig, NULL);
	    }
	  while (c.sig->signal_received == SIGUSR1);

	  uninit_options (&c.options);
	  gc_reset (&c.gc);
	}
      while (c.sig->signal_received == SIGHUP);
    }

  /* uninitialize program-wide statics */
  uninit_static ();

  context_gc_free (&c);

  openvpn_exit (OPENVPN_EXIT_STATUS_GOOD);  /* exit point */
  return 0;			            /* NOTREACHED */
}
