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

#include "memdbg.h"

int
main (int argc, char *argv[])
{
  struct context c;
  const int gc_level = gc_new_level ();

  /* signify first time for components which can
     only be initialized once per program instantiation. */
  c.first_time = true;

  /* initialize program-wide statics */
  init_static ();

  /*
   * This loop is initially executed on startup and then
   * once per SIGHUP.
   */
  do
    {
      context_clear_all_except_first_time (&c);

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
	  const int gc_level_inner = gc_new_level ();

	  context_clear_2 (&c);

	  /* initialize tunnel instance */
	  init_instance (&c);

	  /* main event loop */
	  while (true)
	    {
	      /* process timers, TLS, etc. */
	      pre_select (&c);

	      /* garbage collect */
	      gc_collect (gc_level_inner);

	      /* set up and do the select() */
	      single_select (&c);

	      /* process signals */
	      if (c.sig->signal_received)
		{
		  if (c.sig->signal_received == SIGUSR2)
		    {
		      print_status (&c);
		      c.sig->signal_received = 0;
		      continue;
		    }
		  print_signal (c.sig->signal_received);
		  break;
		}

	      /* timeout? */
	      if (!c.c2.select_status)
		continue;

	      /* process the I/O which triggered select */
	      process_io (&c);

	      if (c.sig->signal_received)
		break;
	    }

	  /* tear down tunnel instance (unless --persist-tun) */
	  close_instance (&c);
	  c.first_time = false;
	  gc_free_level (gc_level_inner);

	}
      while (c.sig->signal_received == SIGUSR1);

      gc_collect (gc_level);

    }
  while (c.sig->signal_received == SIGHUP);

  /* uninitialize program-wide statics */
  uninit_static ();

  /* pop our garbage collection level */
  gc_free_level (gc_level);

  openvpn_exit (OPENVPN_EXIT_STATUS_GOOD);	/* exit point */
  return 0;			/* NOTREACHED */
}
