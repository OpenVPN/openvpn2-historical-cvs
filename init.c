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

#include "win32.h"
#include "init.h"
#include "sig.h"
#include "occ.h"

#include "memdbg.h"

#include "occ-inline.h"

void
context_clear (struct context *c)
{
  CLEAR (*c);
}

void
context_clear_1 (struct context *c)
{
  CLEAR (c->c1);
}

void
context_clear_2 (struct context *c)
{
  CLEAR (c->c2);
}

void
context_clear_all_except_first_time (struct context *c)
{
  const bool first_time_save = c->first_time;
  context_clear (c);
  c->first_time = first_time_save;
}

void
context_init_1 (struct context *c)
{
  CLEAR (c->c1.link_socket_addr);
  clear_tuntap (&c->c1.tuntap);
  CLEAR (c->c1.ks);
  packet_id_persist_init (&c->c1.pid_persist);
  clear_route_list (&c->c1.route_list);
  CLEAR (c->c1.http_proxy);
  CLEAR (c->c1.socks_proxy);

  if (c->options.http_proxy_server)
    {
      init_http_proxy (&c->c1.http_proxy,
		       c->options.http_proxy_server,
		       c->options.http_proxy_port,
		       c->options.http_proxy_retry,
		       c->options.http_proxy_auth_method,
		       c->options.http_proxy_auth_file);
    }

  if (c->options.socks_proxy_server)
    {
      init_socks_proxy (&c->c1.socks_proxy,
			c->options.socks_proxy_server,
			c->options.socks_proxy_port,
			c->options.socks_proxy_retry);
    }
}

bool
init_static (void)
{
  init_random_seed ();		/* init random() function, only used as
				   source for weak random numbers */
  error_reset ();		/* initialize error.c */
  reset_check_status ();	/* initialize status check code in socket.c */

#ifdef PID_TEST
  packet_id_interactive_test ();	/* test the sequence number code */
  return true;
#endif

#ifdef WIN32
  init_win32 ();
#endif

#ifdef OPENVPN_DEBUG_COMMAND_LINE
  {
    int i;
    for (i = 0; i < argc; ++i)
      msg (M_INFO, "argv[%d] = '%s'", i, argv[i]);
  }
#endif

  del_env_nonparm (0);

#ifdef USE_CRYPTO
  init_ssl_lib ();

  /* init PRNG used for IV generation */
  /* JYFIXME -- copy this to more places in the code to avoid fork
     predictability */
  prng_init ();
#endif

  return false;
}

void
uninit_static (void)
{
  thread_cleanup ();

#ifdef USE_CRYPTO
  free_ssl_lib ();
#endif

#if defined(MEASURE_TLS_HANDSHAKE_STATS) && defined(USE_CRYPTO) && defined(USE_SSL)
  show_tls_performance_stats ();
#endif
}

void
init_verb_mute (const struct options *options)
{
  /* set verbosity and mute levels */
  set_check_status (D_LINK_ERRORS, D_READ_WRITE);
  set_debug_level (options->verbosity);
  set_mute_cutoff (options->mute);
}

/*
 * Possibly set --dev based on --dev-node.
 * For example, if --dev-node /tmp/foo/tun, and --dev undefined,
 * set --dev to tun.
 */
void
init_options_dev (struct options *options)
{
  if (!options->dev)
    options->dev = dev_component_in_dev_node (options->dev_node);
}

bool
print_openssl_info (const struct options *options)
{
  /*
   * OpenSSL info print mode?
   */
#ifdef USE_CRYPTO
  if (options->show_ciphers || options->show_digests
#ifdef USE_SSL
      || options->show_tls_ciphers
#endif
    )
    {
      if (options->show_ciphers)
	show_available_ciphers ();
      if (options->show_digests)
	show_available_digests ();
#ifdef USE_SSL
      if (options->show_tls_ciphers)
	show_available_tls_ciphers ();
#endif
      return true;
    }
#endif
  return false;
}

/*
 * Static pre-shared key generation mode?
 */
bool
do_genkey (const struct options * options)
{
#ifdef USE_CRYPTO
  if (options->genkey)
    {
      int nbits_written;

      notnull (options->shared_secret_file,
	       "shared secret output file (--secret)");

      if (options->mlock)	/* should we disable paging? */
	do_mlockall (true);

      nbits_written = write_key_file (2, options->shared_secret_file);

      msg (D_GENKEY | M_NOPREFIX,
	   "Randomly generated %d bit key written to %s", nbits_written,
	   options->shared_secret_file);
      return true;
    }
#endif
  return false;
}

/*
 * Persistent TUN/TAP device management mode?
 */
bool
do_persist_tuntap (const struct options * options)
{
#ifdef TUNSETPERSIST
  if (options->persist_config)
    {
      /* sanity check on options for --mktun or --rmtun */
      notnull (options->dev, "TUN/TAP device (--dev)");
      if (options->remote || options->ifconfig_local
	  || options->ifconfig_remote_netmask
#ifdef USE_CRYPTO
	  || options->shared_secret_file
#ifdef USE_SSL
	  || options->tls_server || options->tls_client
#endif
#endif
	)
	msg (M_FATAL,
	     "Options error: options --mktun or --rmtun should only be used together with --dev");
      tuncfg (options->dev, options->dev_type, options->dev_node,
	      options->tun_ipv6, options->persist_mode);
      return true;
    }
#endif
  return false;
}

/*
 * Should we become a daemon?
 * Return true if we did it.
 */
static bool
possibly_become_daemon (const struct options *options, const bool first_time)
{
  bool ret = false;
  if (first_time && options->daemon)
    {
      ASSERT (!options->inetd);
      if (daemon (options->cd_dir != NULL, options->log) < 0)
	msg (M_ERR, "daemon() failed");
      ret = true;
    }
  return ret;
}

void
pre_setup (const struct options *options)
{
  /* show all option settings */
  show_settings (options);

  /* set certain options as environmental variables */
  setenv_settings (options);

#ifdef WIN32
  /* put a title on the top window bar */
  generate_window_title (options->config ? options->config : "");
#endif

  /* print version number */
  msg (M_INFO, "%s", title_string);
}

/*
 * Initialize the route list, resolving any DNS names in route
 * options and saving routes in the environment.
 */
static void
do_init_route_list (const struct options *options,
		    struct route_list *route_list,
		    struct link_socket *link_socket, bool fatal)
{
  const char *gw = NULL;
  int dev = dev_type_enum (options->dev, options->dev_type);

  if (dev == DEV_TYPE_TUN)
    gw = options->ifconfig_remote_netmask;
  if (options->route_default_gateway)
    gw = options->route_default_gateway;

  if (!init_route_list (route_list,
			&options->routes,
			gw, link_socket_current_remote (link_socket)))
    {
      if (fatal)
	openvpn_exit (OPENVPN_EXIT_STATUS_ERROR);	/* exit point */
    }
  else
    {
      /* copy routes to environment */
      setenv_routes (route_list);
    }
}

/*
 * Possibly add routes and/or call route-up script
 * based on options.
 */
void
do_route (const struct options *options, struct route_list *route_list)
{
  if (!options->route_noexec)
    add_routes (route_list, false);
  if (options->route_script)
    {
      setenv_str ("script_type", "route-up");
      system_check (options->route_script, "Route script failed", false);
    }
}

/*
 * Open tun/tap device, ifconfig, call up script, etc.
 */

bool
do_open_tun (const struct options *options,
	     struct frame *frame,
	     struct link_socket *link_socket,
	     struct tuntap *tuntap, struct route_list *route_list)
{
  bool ret = false;

  if (!tuntap_defined (tuntap))
    {
      /* parse and resolve the route option list */
      do_init_route_list (options, route_list, link_socket, true);

      /* do ifconfig */
      if (!options->ifconfig_noexec
	  && ifconfig_order () == IFCONFIG_BEFORE_TUN_OPEN)
	{
	  /* guess actual tun/tap unit number that will be returned
	     by open_tun */
	  const char *guess = guess_tuntap_dev (options->dev,
						options->dev_type,
						options->dev_node);
	  do_ifconfig (tuntap, guess, TUN_MTU_SIZE (frame));
	}

      /* open the tun device */
      open_tun (options->dev, options->dev_type, options->dev_node,
		options->tun_ipv6, tuntap);

      /* do ifconfig */
      if (!options->ifconfig_noexec
	  && ifconfig_order () == IFCONFIG_AFTER_TUN_OPEN)
	do_ifconfig (tuntap, tuntap->actual, TUN_MTU_SIZE (frame));

      /* run the up script */
      run_script (options->up_script,
		  tuntap->actual,
		  TUN_MTU_SIZE (frame),
		  MAX_RW_SIZE_LINK (frame),
		  print_in_addr_t (tuntap->local, true),
		  print_in_addr_t (tuntap->remote_netmask, true),
		  "init", NULL, "up");

      /* possibly add routes */
      if (!options->route_delay_defined)
	do_route (options, route_list);

      /*
       * Did tun/tap driver give us an MTU?
       */
      if (tuntap->post_open_mtu)
	frame_set_mtu_dynamic (frame,
			       tuntap->post_open_mtu,
			       SET_MTU_TUN | SET_MTU_UPPER_BOUND);

      /*
       * On Windows, it is usually wrong if --tun-mtu != 1500.
       */
#ifdef WIN32
      if (TUN_MTU_SIZE (frame) != 1500)
	msg (M_WARN,
	     "WARNING: in general you should use '--tun-mtu 1500 --mssfix 1400' on both sides of the connection if at least one side is running Windows, unless you have explicitly modified the TAP-Win32 driver properties");
#endif

      ret = true;
    }
  else
    {
      msg (M_INFO, "Preserving previous TUN/TAP instance: %s",
	   tuntap->actual);

      /* run the up script if user specified --up-restart */
      if (options->up_restart)
	run_script (options->up_script,
		    tuntap->actual,
		    TUN_MTU_SIZE (frame),
		    MAX_RW_SIZE_LINK (frame),
		    print_in_addr_t (tuntap->local, true),
		    print_in_addr_t (tuntap->remote_netmask, true),
		    "restart", NULL, "up");
    }
  return ret;
}

/*
 * Depending on protocol, sleep before restart to prevent
 * TCP race.
 */
static void
socket_restart_pause (int proto, bool http_proxy, bool socks_proxy)
{
  int sec = 0;
  switch (proto)
    {
    case PROTO_UDPv4:
      sec = socks_proxy ? 3 : 0;
      break;
    case PROTO_TCPv4_SERVER:
      sec = 1;
      break;
    case PROTO_TCPv4_CLIENT:
      sec = (http_proxy || socks_proxy) ? 10 : 3;
      break;
    }
  if (sec)
    {
      msg (D_RESTART, "Restart pause, %d second(s)", sec);
      sleep (sec);
    }
}

/*
 * Finalize MTU parameters based on command line or config file options.
 */
static void
frame_finalize_options (struct frame *frame, const struct options *options)
{

  frame_finalize (frame,
		  options->link_mtu_defined,
		  options->link_mtu,
		  options->tun_mtu_defined, options->tun_mtu);
}

/*
 * Free a key schedule, including OpenSSL components.
 */
static void
key_schedule_free (struct key_schedule *ks)
{
#ifdef USE_CRYPTO
  free_key_ctx_bi (&ks->static_key);
#ifdef USE_SSL
  if (ks->ssl_ctx)
    SSL_CTX_free (ks->ssl_ctx);
  free_key_ctx_bi (&ks->tls_auth_key);
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
  CLEAR (*ks);
}

#ifdef USE_CRYPTO

static void
init_crypto_pre (struct context *c)
{
  /* load a persisted packet-id for cross-session replay-protection */
  if (c->options.packet_id_file)
    packet_id_persist_load (&c->c1.pid_persist, c->options.packet_id_file);

  /* Initialize crypto options */
  c->c2.crypto_options.use_iv = c->options.use_iv;
}

/*
 * Static Key Mode (using a pre-shared key)
 */
static void
do_init_crypto_static (struct context *c)
{
  const struct options *options = &c->options;
  ASSERT (options->shared_secret_file);

  init_crypto_pre (c);

  /* Initialize packet ID tracking */
  if (options->replay)
    {
      packet_id_init (&c->c2.packet_id, options->replay_window,
		      options->replay_time);
      c->c2.crypto_options.packet_id = &c->c2.packet_id;
      c->c2.crypto_options.pid_persist = &c->c1.pid_persist;
      c->c2.crypto_options.packet_id_long_form = true;
      packet_id_persist_load_obj (&c->c1.pid_persist,
				  c->c2.crypto_options.packet_id);
    }

  if (!key_ctx_bi_defined (&c->c1.ks.static_key))
    {
      struct key2 key2;
      struct key_direction_state kds;

      /* Get cipher & hash algorithms */
      init_key_type (&c->c1.ks.key_type, options->ciphername,
		     options->ciphername_defined, options->authname,
		     options->authname_defined, options->keysize,
		     options->test_crypto, true);

      /* Read cipher and hmac keys from shared secret file */
      read_key_file (&key2, options->shared_secret_file, true);

      /* Check for and fix highly unlikely key problems */
      verify_fix_key2 (&key2, &c->c1.ks.key_type,
		       options->shared_secret_file);

      /* Initialize OpenSSL key objects */
      key_direction_state_init (&kds, options->key_direction);
      must_have_n_keys (options->shared_secret_file, "secret", &key2,
			kds.need_keys);
      init_key_ctx (&c->c1.ks.static_key.encrypt, &key2.keys[kds.out_key],
		    &c->c1.ks.key_type, DO_ENCRYPT, "Static Encrypt");
      init_key_ctx (&c->c1.ks.static_key.decrypt, &key2.keys[kds.in_key],
		    &c->c1.ks.key_type, DO_DECRYPT, "Static Decrypt");

      /* Erase the temporary copy of key */
      CLEAR (key2);
    }
  else
    {
      msg (M_INFO, "Re-using pre-shared static key");
    }

  /* Get key schedule */
  c->c2.crypto_options.key_ctx_bi = &c->c1.ks.static_key;

  /* Compute MTU parameters */
  crypto_adjust_frame_parameters (&c->c2.frame,
				  &c->c1.ks.key_type,
				  options->ciphername_defined,
				  options->use_iv, options->replay, true);

  /* Sanity check on IV, sequence number, and cipher mode options */
  check_replay_iv_consistency (&c->c1.ks.key_type, options->replay,
			       options->use_iv);
}

#ifdef USE_SSL

static void
do_init_crypto_tls (struct context *c)
{
  const struct options *options = &c->options;
  struct tls_options to;
  bool packet_id_long_form;

  ASSERT (options->tls_server || options->tls_client);
  ASSERT (!options->test_crypto);

  init_crypto_pre (c);

  /* Make sure we are either a TLS client or server but not both */
  ASSERT (options->tls_server == !options->tls_client);

  /* Let user specify a script to verify the incoming certificate */
  tls_set_verify_command (options->tls_verify);

  /* Verify the X509 name of the incoming host */
  tls_set_verify_x509name (options->tls_remote);

  /* Let user specify a certificate revocation list to
     check the incoming certificate */
  tls_set_crl_verify (options->crl_file);

  if (!c->c1.ks.ssl_ctx)
    {
      /*
       * Initialize the OpenSSL library's global
       * SSL context.
       */
      c->c1.ks.ssl_ctx = init_ssl (options->tls_server,
				   options->ca_file,
				   options->dh_file,
				   options->cert_file,
				   options->priv_key_file,
				   options->cipher_list);

      /* Get cipher & hash algorithms */
      init_key_type (&c->c1.ks.key_type, options->ciphername,
		     options->ciphername_defined, options->authname,
		     options->authname_defined, options->keysize, true, true);

      /* TLS handshake authentication (--tls-auth) */
      if (options->tls_auth_file)
	get_tls_handshake_key (&c->c1.ks.key_type,
			       &c->c1.ks.tls_auth_key,
			       options->tls_auth_file,
			       options->key_direction);
    }
  else
    {
      msg (M_INFO, "Re-using SSL/TLS context");
    }

  /* Sanity check on IV, sequence number, and cipher mode options */
  check_replay_iv_consistency (&c->c1.ks.key_type, options->replay,
			       options->use_iv);

  /* In short form, unique datagram identifier is 32 bits, in long form 64 bits */
  packet_id_long_form = cfb_ofb_mode (&c->c1.ks.key_type);

  /* Compute MTU parameters */
  crypto_adjust_frame_parameters (&c->c2.frame,
				  &c->c1.ks.key_type,
				  options->ciphername_defined,
				  options->use_iv,
				  options->replay, packet_id_long_form);
  tls_adjust_frame_parameters (&c->c2.frame);

  /* Set all command-line TLS-related options */
  CLEAR (to);
  to.ssl_ctx = c->c1.ks.ssl_ctx;
  to.key_type = c->c1.ks.key_type;
  to.server = options->tls_server;
  to.key_method = options->key_method;
  to.replay = options->replay;
  to.packet_id_long_form = packet_id_long_form;
  to.replay_window = options->replay_window;
  to.replay_time = options->replay_time;
  to.transition_window = options->transition_window;
  to.handshake_window = options->handshake_window;
  to.packet_timeout = options->tls_timeout;
  to.renegotiate_bytes = options->renegotiate_bytes;
  to.renegotiate_packets = options->renegotiate_packets;
  to.renegotiate_seconds = options->renegotiate_seconds;
  to.single_session = options->single_session;
  to.disable_occ = !options->occ;

  /* TLS handshake authentication (--tls-auth) */
  if (options->tls_auth_file)
    {
      to.tls_auth_key = c->c1.ks.tls_auth_key;
      to.tls_auth.pid_persist = &c->c1.pid_persist;
      to.tls_auth.packet_id_long_form = true;
      crypto_adjust_frame_parameters (&to.frame,
				      &c->c1.ks.key_type,
				      false, false, true, true);
    }

  /* If we are running over TCP, allow for
     length prefix */
  socket_adjust_frame_parameters (&to.frame, options->proto);

  /*
   * Initialize OpenVPN's master TLS-mode object.
   */
  c->c2.tls_multi = tls_multi_init (&to);
}

static void
do_init_finalize_tls_frame (struct context *c)
{
  tls_multi_init_finalize (c->c2.tls_multi, &c->c2.frame);
  ASSERT (MAX_RW_SIZE_LINK (&c->c2.tls_multi->opt.frame) <=
	  MAX_RW_SIZE_LINK (&c->c2.frame));
  frame_print (&c->c2.tls_multi->opt.frame, D_MTU_INFO,
	       "Control Channel MTU parms");
}

#endif /* USE_SSL */
#endif /* USE_CRYPTO */

#ifdef USE_CRYPTO
/*
 * No encryption or authentication.
 */
static void
do_init_crypto_none (const struct context *c)
{
  ASSERT (!c->options.test_crypto);
  msg (M_WARN,
       "******* WARNING *******: all encryption and authentication features disabled -- all data will be tunnelled as cleartext");
}
#endif

static void
do_init_crypto (struct context *c)
{
#ifdef USE_CRYPTO
  if (c->options.shared_secret_file)
    do_init_crypto_static (c);
#ifdef USE_SSL
  else if (c->options.tls_server || c->options.tls_client)
    do_init_crypto_tls (c);
#endif
  else				/* no encryption or authentication. */
    do_init_crypto_none (c);
#else /* USE_CRYPTO */
  msg (M_WARN,
       "******* WARNING *******: " PACKAGE_NAME
       " built without OpenSSL -- encryption and authentication features disabled -- all data will be tunnelled as cleartext");
#endif /* USE_CRYPTO */
}

static void
do_init_frame (struct context *c)
{
#ifdef USE_LZO
  /*
   * Initialize LZO compression library.
   */
  if (c->options.comp_lzo)
    {
      lzo_adjust_frame_parameters (&c->c2.frame);
      lzo_adjust_frame_parameters (&c->c2.frame_fragment_omit);	/* omit LZO frame delta from final frame_fragment */
    }
#endif

  /*
   * Adjust frame size for UDP Socks support.
   */
  if (c->options.socks_proxy_server)
    socks_adjust_frame_parameters (&c->c2.frame, c->options.proto);

  /*
   * Adjust frame size based on the --tun-mtu-extra parameter.
   */
  if (c->options.tun_mtu_extra_defined)
    tun_adjust_frame_parameters (&c->c2.frame, c->options.tun_mtu_extra);

  /*
   * Adjust frame size based on link socket parameters.
   * (Since TCP is a stream protocol, we need to insert
   * a packet length uint16_t in the buffer.)
   */
  socket_adjust_frame_parameters (&c->c2.frame, c->options.proto);

  /*
   * Fill in the blanks in the frame parameters structure,
   * make sure values are rational, etc.
   */
  frame_finalize_options (&c->c2.frame, &c->options);

  /*
   * Set frame parameter for fragment code.  This is necessary because
   * the fragmentation code deals with payloads which have already been
   * passed through the compression code.
   */
  c->c2.frame_fragment = c->c2.frame;
  frame_subtract_extra (&c->c2.frame_fragment, &c->c2.frame_fragment_omit);

  /*
   * MTU advisories
   */
  if (c->options.fragment && c->options.mtu_test)
    msg (M_WARN,
	 "WARNING: using --fragment and --mtu-test together may produce an inaccurate MTU test result");

  if ((c->options.mssfix || c->options.fragment)
      && TUN_MTU_SIZE (&c->c2.frame_fragment) != ETHERNET_MTU)
    msg (M_WARN,
	 "WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu %d (currently it is %d)",
	 ETHERNET_MTU, TUN_MTU_SIZE (&c->c2.frame_fragment));

}

static void
do_init_frame_tls (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->c2.tls_multi)
    do_init_finalize_tls_frame (c);
#endif
}

/*
 * Now that we know all frame parameters, initialize
 * our buffers.
 */
static void
do_init_buffers (struct context *c)
{
  c->c2.read_link_buf = alloc_buf (BUF_SIZE (&c->c2.frame));
  c->c2.read_tun_buf = alloc_buf (BUF_SIZE (&c->c2.frame));
  c->c2.aux_buf = alloc_buf (BUF_SIZE (&c->c2.frame));

#ifdef USE_CRYPTO
  c->c2.encrypt_buf = alloc_buf (BUF_SIZE (&c->c2.frame));
  c->c2.decrypt_buf = alloc_buf (BUF_SIZE (&c->c2.frame));
#endif

#ifdef USE_LZO
  if (c->options.comp_lzo)
    {
      c->c2.lzo_compress_buf = alloc_buf (BUF_SIZE (&c->c2.frame));
      c->c2.lzo_decompress_buf = alloc_buf (BUF_SIZE (&c->c2.frame));
    }
#endif
}

/*
 * Fragmenting code has buffers to initialize
 * once frame parameters are known.
 */
static void
do_init_fragment (struct context *c)
{
  ASSERT (c->options.fragment);
  frame_set_mtu_dynamic (&c->c2.frame_fragment,
			 c->options.fragment, SET_MTU_UPPER_BOUND);
  fragment_frame_init (c->c2.fragment, &c->c2.frame_fragment);
}

/*
 * Set the dynamic MTU parameter, used by the --mssfix
 * option.  If --mssfix is supplied without a parameter,
 * then default to --fragment size.  Otherwise default
 * to udp_mtu or (on Windows) TAP-Win32 mtu size which
 * is set in the adapter advanced properties dialog.
 */
static void
do_init_dynamic_mtu (struct context *c)
{
  if (c->options.mssfix_defined)
    {
      if (c->options.mssfix)
	{
	  frame_set_mtu_dynamic (&c->c2.frame,
				 c->options.mssfix, SET_MTU_UPPER_BOUND);
	}
      else if (c->c2.fragment)
	{
	  frame_set_mtu_dynamic (&c->c2.frame,
				 EXPANDED_SIZE_DYNAMIC (&c->c2.
							frame_fragment),
				 SET_MTU_UPPER_BOUND);
	}
    }
}

/*
 * bind the TCP/UDP socket
 */
static void
do_init_socket_1 (struct context *c)
{
  link_socket_init_phase1 (&c->c2.link_socket,
			   c->options.local, c->options.remote,
			   c->options.local_port, c->options.remote_port,
			   c->options.proto,
			   c->c1.http_proxy.defined ? &c->c1.
			   http_proxy : NULL,
			   c->c1.socks_proxy.defined ? &c->c1.
			   socks_proxy : NULL, c->options.bind_local,
			   c->options.remote_float, c->options.inetd,
			   &c->c1.link_socket_addr, c->options.ipchange,
			   c->options.resolve_retry_seconds,
			   c->options.connect_retry_seconds,
			   c->options.mtu_discover_type);
}

/*
 * finalize the TCP/UDP socket
 */
static void
do_init_socket_2 (struct context *c)
{
  link_socket_init_phase2 (&c->c2.link_socket, &c->c2.frame,
			   &c->sig->signal_received);
}

/*
 * initialize tun/tap device object
 */
static void
do_init_tun (struct context *c)
{
  init_tun (&c->c1.tuntap,
	    c->options.dev,
	    c->options.dev_type,
	    c->options.ifconfig_local,
	    c->options.ifconfig_remote_netmask,
	    addr_host (&c->c2.link_socket.lsa->local),
	    addr_host (&c->c2.link_socket.lsa->remote),
	    &c->c2.frame, c->options.tuntap_flags);
}

/*
 * Print MTU INFO
 */
static void
do_print_data_channel_mtu_parms (struct context *c)
{
  frame_print (&c->c2.frame, D_MTU_INFO, "Data Channel MTU parms");
  if (c->c2.fragment)
    frame_print (&c->c2.frame_fragment, D_MTU_INFO,
		 "Fragmentation MTU parms");
}

/*
 * Get local and remote options compatibility strings.
 */
static void
do_compute_occ_strings (struct context *c)
{
  c->c2.options_string_local =
    options_string (&c->options, &c->c2.frame, &c->c1.tuntap, false);
  c->c2.options_string_remote =
    options_string (&c->options, &c->c2.frame, &c->c1.tuntap, true);

  msg (D_SHOW_OCC, "Local Options String: '%s'", c->c2.options_string_local);
  msg (D_SHOW_OCC, "Expected Remote Options String: '%s'",
       c->c2.options_string_remote);

#ifdef USE_CRYPTO
  msg (D_SHOW_OCC_HASH, "Local Options hash (VER=%s): '%s'",
       options_string_version (c->c2.options_string_local),
       md5sum (c->c2.options_string_local,
	       strlen (c->c2.options_string_local), 9));
  msg (D_SHOW_OCC_HASH, "Expected Remote Options hash (VER=%s): '%s'",
       options_string_version (c->c2.options_string_remote),
       md5sum (c->c2.options_string_remote,
	       strlen (c->c2.options_string_remote), 9));
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->c2.tls_multi)
    tls_multi_init_set_options (c->c2.tls_multi,
				c->c2.options_string_local,
				c->c2.options_string_remote);
#endif
}

/*
 * Initialize traffic shaper.
 */
static void
do_init_traffic_shaper (struct context *c)
{
#ifdef HAVE_GETTIMEOFDAY
  /* initialize traffic shaper (i.e. transmit bandwidth limiter) */
  if (c->options.shaper)
    {
      shaper_init (&c->c2.shaper, c->options.shaper);
      shaper_msg (&c->c2.shaper);
    }
#endif
}

/*
 * These things can only be executed once per program instantiation.
 */
static void
do_init_first_time_1 (struct context *c)
{
  if (c->first_time)
    {
      /* get user and/or group that we want to setuid/setgid to */
      get_group (c->options.groupname, &c->c2.group_state);
      get_user (c->options.username, &c->c2.user_state);

      /* get --writepid file descriptor */
      get_pid_file (c->options.writepid, &c->c2.pid_state);

      /* chroot if requested */
      if (c->options.chroot_dir)
	do_chroot (c->options.chroot_dir);
    }

  /* become a daemon if --daemon */
  c->c2.did_we_daemonize =
    possibly_become_daemon (&c->options, c->first_time);
}

/*
 * Do first-time initialization AFTER possible daemonization,
 * UID/GID downgrade, and chroot.
 */
static void
do_init_first_time_2 (struct context *c)
{
  if (c->first_time)
    {
      /* should we disable paging? */
      if (c->options.mlock && c->c2.did_we_daemonize)
	do_mlockall (true);	/* call again in case we daemonized */

      /* should we change scheduling priority? */
      set_nice (c->options.nice);

      /* set user and/or group that we want to setuid/setgid to */
      set_group (&c->c2.group_state);
      set_user (&c->c2.user_state);

      /* save process ID in a file */
      write_pid (&c->c2.pid_state);
    }
}

/*
 * Start the TLS thread
 */
static void
do_start_tls_thread (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
  if (c->c2.tls_multi && c->options.tls_thread)
    {
      if (c->first_time)
	thread_init ();
      tls_thread_create (&c->c2.thread_parms, c->c2.tls_multi,
			 &c->c2.link_socket, c->options.nice_work,
			 c->options.mlock);
      c->c2.thread_opened = true;
    }
#endif
}

/*
 * set maximum fd + 1 for select()
 */
static void
do_init_maxfd (struct context *c)
{
  SOCKET_SETMAXFD (&c->c2.event_wait, &c->c2.link_socket);
  TUNTAP_SETMAXFD (&c->c2.event_wait, &c->c1.tuntap);

#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
  if (c->options.tls_thread)
    {
      TLS_THREAD_SOCKET_SETMAXFD (c->c2.tls_multi, &c->c2.event_wait,
				  &c->c2.thread_parms);
    }
#endif
}

/*
 * initialize timers
 */
void
do_init_timers (struct context *c)
{
  c->c2.current = time (NULL);

  /* initialize connection establishment timer */
  event_timeout_init (&c->c2.wait_for_connect, c->c2.current, 5);

  /* initialize inactivity timeout */
  if (c->options.inactivity_timeout)
    event_timeout_init (&c->c2.inactivity_interval, c->c2.current,
			c->options.inactivity_timeout);

  /* initialize pings */

  if (c->options.ping_send_timeout)
    event_timeout_init (&c->c2.ping_send_interval, 0,
			c->options.ping_send_timeout);

  if (c->options.ping_rec_timeout)
    event_timeout_init (&c->c2.ping_rec_interval, c->c2.current,
			c->options.ping_rec_timeout);

  /* initialize occ timers */

  if (c->options.occ
      && !TLS_MODE
      && c->c2.options_string_local && c->c2.options_string_remote)
    event_timeout_init (&c->c2.occ_interval, c->c2.current,
			OCC_INTERVAL_SECONDS);

  if (c->options.mtu_test)
    event_timeout_init (&c->c2.occ_mtu_load_test_interval, c->c2.current,
			OCC_MTU_LOAD_INTERVAL_SECONDS);

#if defined(USE_CRYPTO) && defined(USE_SSL)
#ifdef USE_PTHREAD
  if (!c->options.tls_thread)
#endif
    /* initialize tmp_int optimization that limits the number of times we call
       tls_multi_process in the main event loop */
    interval_init (&c->c2.tmp_int, TLS_MULTI_HORIZON, TLS_MULTI_REFRESH);
#endif
}

/*
 * If xinetd/inetd mode, don't allow restart.
 */
static void
do_close_check_if_restart_permitted (struct context *c)
{
  if (c->options.inetd
      && (c->sig->signal_received == SIGHUP
	  || c->sig->signal_received == SIGUSR1))
    {
      c->sig->signal_received = SIGTERM;
      msg (M_INFO,
	   PACKAGE_NAME
	   " started by inetd/xinetd cannot restart... Exiting.");
    }
}

/*
 * close TLS thread
 */
static void
do_close_tls_thread (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
  if (c->c2.thread_opened)
    tls_thread_close (&c->c2.thread_parms);
#endif
}

/*
 * free buffers
 */
static void
do_close_free_buf (struct context *c)
{
  if (c->c2.free_to_link)
    free_buf (&c->c2.to_link);

  free_buf (&c->c2.read_link_buf);
  free_buf (&c->c2.read_tun_buf);
  free_buf (&c->c2.aux_buf);

#ifdef USE_LZO
  if (c->options.comp_lzo)
    {
      free_buf (&c->c2.lzo_compress_buf);
      free_buf (&c->c2.lzo_decompress_buf);
    }
#endif

#ifdef USE_CRYPTO
  free_buf (&c->c2.encrypt_buf);
  free_buf (&c->c2.decrypt_buf);
#endif
}

/*
 * close TLS
 */
static void
do_close_tls (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (c->c2.tls_multi)
    tls_multi_free (c->c2.tls_multi, true);

  /* free options compatibility strings */
  if (c->c2.options_string_local)
    free (c->c2.options_string_local);
  if (c->c2.options_string_remote)
    free (c->c2.options_string_remote);
#endif
}

/*
 * Free key schedules
 */
static void
do_close_free_key_schedule (struct context *c)
{
  if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_key))
    key_schedule_free (&c->c1.ks);
}

/*
 * Close TCP/UDP connection
 */
static void
do_close_link_socket (struct context *c)
{
  link_socket_close (&c->c2.link_socket);
  if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_remote_ip))
    {
      CLEAR (c->c1.link_socket_addr.remote);
      CLEAR (c->c1.link_socket_addr.actual);
    }
  if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_local_ip))
    CLEAR (c->c1.link_socket_addr.local);
}

/*
 * Close TUN/TAP device
 */
static void
do_close_tuntap (struct context *c)
{
  if (tuntap_defined (&c->c1.tuntap))
    {
      if (!(c->sig->signal_received == SIGUSR1 && c->options.persist_tun))
	{
	  char *tuntap_actual =
	    (char *) gc_malloc (sizeof (c->c1.tuntap.actual));
	  strcpy (tuntap_actual, c->c1.tuntap.actual);

	  /* delete any routes we added */
	  delete_routes (&c->c1.route_list);

	  msg (D_CLOSE, "Closing TUN/TAP device");
	  close_tun (&c->c1.tuntap);

	  /* Run the down script -- note that it will run at reduced
	     privilege if, for example, "--user nobody" was used. */
	  run_script (c->options.down_script,
		      tuntap_actual,
		      TUN_MTU_SIZE (&c->c2.frame),
		      MAX_RW_SIZE_LINK (&c->c2.frame),
		      print_in_addr_t (c->c1.tuntap.local, true),
		      print_in_addr_t (c->c1.tuntap.remote_netmask, true),
		      "init",
		      signal_description (c->sig->signal_received,
					  c->sig->signal_text), "down");
	}
      else
	{
	  /* run the down script on this restart if --up-restart was specified */
	  if (c->options.up_restart)
	    run_script (c->options.down_script,
			c->c1.tuntap.actual,
			TUN_MTU_SIZE (&c->c2.frame),
			MAX_RW_SIZE_LINK (&c->c2.frame),
			print_in_addr_t (c->c1.tuntap.local, true),
			print_in_addr_t (c->c1.tuntap.remote_netmask, true),
			"restart",
			signal_description (c->sig->signal_received,
					    c->sig->signal_text), "down");
	}
    }
}

/*
 * Remove non-parameter environmental vars except for signal
 */
static void
do_close_remove_env (struct context *c)
{
  del_env_nonparm (
#if defined(USE_CRYPTO) && defined(USE_SSL)
		    get_max_tls_verify_id ()
#else
		    0
#endif
    );
}

/*
 * Close packet-id persistance file
 */
static void
do_close_packet_id (struct context *c)
{
#ifdef USE_CRYPTO
  packet_id_free (&c->c2.packet_id);
  packet_id_persist_save (&c->c1.pid_persist);
  if (!(c->sig->signal_received == SIGUSR1))
    packet_id_persist_close (&c->c1.pid_persist);
#endif
}

/*
 * Close fragmentation handler.
 */
static void
do_close_fragment (struct context *c)
{
  if (c->c2.fragment)
    fragment_free (c->c2.fragment);
}

/*
 * Close syslog
 */
static void
do_close_syslog (struct context *c)
{
  if (!(c->sig->signal_received == SIGUSR1))
    close_syslog ();
}

/*
 * Initialize a tunnel instance.
 */
void
init_instance (struct context *c)
{
  const struct options *options = &c->options;

  /* signals caught here will abort */
  c->sig->signal_received = 0;
  c->sig->signal_text = NULL;
  pre_init_signal_catch ();

  /* init flags */
  c->c2.ipv4_tun = (!options->tun_ipv6
		    && is_dev_type (options->dev, options->dev_type, "tun"));
  c->c2.log_rw = (check_debug_level (D_LOG_RW)
		  && !check_debug_level (D_LOG_RW + 1));

  /* possible sleep if restart */
  if (!c->first_time)
    socket_restart_pause (options->proto, options->http_proxy_server != NULL,
			  options->socks_proxy_server != NULL);

  /* reset OCC state */
  c->c2.occ_op = occ_reset_op ();

  /* our wait-for-i/o object, different for posix vs. win32 */
  wait_init (&c->c2.event_wait);

  /* reset our transport layer socket object */
  link_socket_reset (&c->c2.link_socket);

  /* should we disable paging? */
  if (c->first_time && options->mlock)
    do_mlockall (true);

  /* initialize internal fragmentation object */
  if (options->fragment)
    c->c2.fragment = fragment_init (&c->c2.frame);

  /* init crypto layer */
  do_init_crypto (c);

#ifdef USE_LZO
  /* initialize LZO compression library. */
  if (options->comp_lzo)
    lzo_compress_init (&c->c2.lzo_compwork, options->comp_lzo_adaptive);
#endif

  /* initialize MTU variables */
  do_init_frame (c);

  /* initialize TLS MTU variables */
  do_init_frame_tls (c);

  /* init workspace buffers whose size is derived from frame size */
  do_init_buffers (c);

  /* initialize internal fragmentation capability with known frame size */
  if (options->fragment)
    do_init_fragment (c);

  /* initialize dynamic MTU variable */
  do_init_dynamic_mtu (c);

  /* bind the TCP/UDP socket */
  do_init_socket_1 (c);

  /* initialize tun/tap device object */
  do_init_tun (c);

  /* open tun/tap device, ifconfig, run up script, etc. */
  if (!options->up_delay)
    c->c2.did_open_tun =
      do_open_tun (options, &c->c2.frame, &c->c2.link_socket, &c->c1.tuntap,
		   &c->c1.route_list);

  /* print MTU info */
  do_print_data_channel_mtu_parms (c);

  /* get local and remote options compatibility strings */
  do_compute_occ_strings (c);

  /* initialize output speed limiter */
  do_init_traffic_shaper (c);

  /* do one-time inits, and possibily become a daemon here */
  do_init_first_time_1 (c);

  /* catch signals */
  post_init_signal_catch ();

  /*
   * Do first-time initialization AFTER possible daemonization,
   * UID/GID downgrade, and chroot.
   */
  do_init_first_time_2 (c);

  /* finalize the TCP/UDP socket */
  do_init_socket_2 (c);
  if (c->sig->signal_received)
    {
      c->sig->signal_text = "socket";
      print_signal (c->sig->signal_received);
      return;
    }

  /* start the TLS thread */
  do_start_tls_thread (c);

  /* set maximum fd + 1 for select() */
  do_init_maxfd (c);

  /* initialize timers */
  do_init_timers (c);
}

/*
 * Close a tunnel instance.
 */
void
close_instance (struct context *c)
{
  /* if xinetd/inetd mode, don't allow restart */
  do_close_check_if_restart_permitted (c);

  /* close TLS thread */
  do_close_tls_thread (c);

#ifdef USE_LZO
  if (c->options.comp_lzo)
    lzo_compress_uninit (&c->c2.lzo_compwork);
#endif

  /* free buffers */
  do_close_free_buf (c);

  /* close TLS */
  do_close_tls (c);

  /* free key schedules */
  do_close_free_key_schedule (c);

  /* close TCP/UDP connection */
  do_close_link_socket (c);

  /* close TUN/TAP device */
  do_close_tuntap (c);

  /* remove non-parameter environmental vars except for signal */
  do_close_remove_env (c);

  /* close packet-id persistance file */
  do_close_packet_id (c);

  /* close fragmentation handler */
  do_close_fragment (c);

  /* close syslog */
  do_close_syslog (c);
}

#ifdef USE_CRYPTO

/*
 * Do a loopback test
 * on the crypto subsystem.
 */
static void *
test_crypto_thread (void *arg)
{
  struct context *c = (struct context *) arg;
  const struct options *options = &c->options;
#if defined(USE_PTHREAD) && defined(USE_SSL)
  struct context *child = NULL;
#endif

  ASSERT (options->test_crypto);
  context_init_1 (c);
  init_crypto_pre (c);

#if defined(USE_PTHREAD) && defined(USE_SSL)
  {
    if (c->first_time && options->tls_thread)
      {
	thread_init ();
	child = (struct context *) malloc (sizeof (struct context));
	context_clear (child);
	child->options = *options;
	child->first_time = false;
	work_thread_create (test_crypto_thread, (void *) child);
      }
  }
#endif
  frame_finalize_options (&c->c2.frame, options);

  test_crypto (&c->c2.crypto_options, &c->c2.frame);
  key_schedule_free (&c->c1.ks);

#if defined(USE_PTHREAD) && defined(USE_SSL)
  if (c->first_time && options->tls_thread)
    work_thread_join ();
  if (child)
    free (child);
#endif
  return NULL;
}

#endif

bool
do_test_crypto (const struct options *o)
{
#ifdef USE_CRYPTO
  if (o->test_crypto)
    {
      struct context c;
      context_clear (&c);
      c.options = *o;
      c.first_time = true;
      test_crypto_thread ((void *) &c);
      return true;
    }
#endif
  return false;
}
