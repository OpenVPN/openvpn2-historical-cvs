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

#include "forward.h"
#include "init.h"
#include "gremlin.h"
#include "mss.h"

#include "memdbg.h"

#include "forward-inline.h"
#include "occ-inline.h"
#include "ping-inline.h"

/* show pre-select debugging info */

void
show_select_status (struct context *c)
{
  msg (D_SELECT, "SELECT %s|%s|%s|%s %d/%d",
       TUNTAP_READ_STAT (&c->c2.event_wait, &c->c1.tuntap),
       TUNTAP_WRITE_STAT (&c->c2.event_wait, &c->c1.tuntap),
       SOCKET_READ_STAT (&c->c2.event_wait, &c->c2.link_socket),
       SOCKET_WRITE_STAT (&c->c2.event_wait, &c->c2.link_socket),
       (int) c->c2.timeval.tv_sec, (int) c->c2.timeval.tv_usec);
}

/*
 * In TLS mode, let TLS level respond to any control-channel
 * packets which were received, or prepare any packets for
 * transmission.
 *
 * tmp_int is purely an optimization that allows us to call
 * tls_multi_process less frequently when there's not much
 * traffic on the control-channel.
 *
 */
#if defined(USE_CRYPTO) && defined(USE_SSL)
void
check_tls_dowork (struct context *c)
{
  interval_t wakeup = BIG_TIMEOUT;

  if (interval_test (&c->c2.tmp_int, c->c2.current))
    {
      if (tls_multi_process
	  (c->c2.tls_multi, &c->c2.to_link, &c->c2.to_link_addr,
	   &c->c2.link_socket, &wakeup, c->c2.current))
	{
	  c->c2.current = time (NULL);
	  interval_action (&c->c2.tmp_int, c->c2.current);
	}

      interval_future_trigger (&c->c2.tmp_int, wakeup, c->c2.current);
      c->c2.free_to_link = false;
    }

  interval_schedule_wakeup (&c->c2.tmp_int, c->c2.current, &wakeup);

  if (wakeup)
    {
      c->c2.timeval.tv_sec = wakeup;
      c->c2.timeval.tv_usec = 0;
    }
}
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL)
void
check_tls_errors_dowork (struct context *c)
{
  /* TLS errors are fatal in TCP mode */
  c->sig->signal_received = SIGUSR1;
  msg (D_STREAM_ERRORS, "Fatal decryption error, restarting");
  c->sig->signal_text = "tls-error";
}
#endif

/*
 * Handle incoming configuration
 * messages on the control channel.
 *
 * JYFIXME -- actually do something with incoming config message
 */
#if defined(USE_CRYPTO) && defined(USE_SSL)
void
check_incoming_control_channel_dowork (struct context *c)
{
  const int len = tls_test_payload_len (c->c2.tls_multi);
  if (len)
    {
      struct buffer buf = alloc_buf (len);
      if (tls_rec_payload (c->c2.tls_multi, &buf))
	{
	  msg (D_LOW, "RECEIVE PAYLOAD: %s", BSTR (&buf));
	}
      else
	{
	  msg (D_LOW, "RECEIVE PAYLOAD FAILED");
	}
      free_buf (&buf);
    }
}
#endif

/*
 * Things that need to happen immediately after connection initiation should go here.
 */
void
check_connection_established_dowork (struct context *c)
{
  if (event_timeout_trigger
      (&c->c2.wait_for_connect, c->c2.current, &c->c2.timeval))
    {
      if (CONNECTION_ESTABLISHED (&c->c2.link_socket))
	{
	  /* if --up-delay specified, open tun, do ifconfig, and run up script now */
	  if (c->options.up_delay)
	    {
	      c->c2.did_open_tun =
		do_open_tun (&c->options, &c->c2.frame, &c->c2.link_socket,
			     &c->c1.tuntap, &c->c1.route_list);
	      TUNTAP_SETMAXFD (&c->c2.event_wait, &c->c1.tuntap);
	      c->c2.current = time (NULL);
	    }

	  if (c->c2.did_open_tun)
	    {
	      /* if --route-delay was specified, start timer */
	      if (c->options.route_delay_defined)
		event_timeout_init (&c->c2.route_wakeup, c->c2.current,
				    c->options.route_delay);
	    }

#if 1 // JYFIXME -- send a test control channel config message
#if defined(USE_CRYPTO) && defined(USE_SSL)
	  {
	    char bigstring[] = "This is a test";
	    struct buffer buf;
	    bool stat;
	    buf_set_read (&buf, bigstring, strlen (bigstring) + 1);
	    stat = tls_send_payload (c->c2.tls_multi, &buf);
	    interval_action (&c->c2.tmp_int, c->c2.current);
	    c->c2.timeval.tv_sec = 0;
	    c->c2.timeval.tv_usec = 0;
	    msg (D_LOW, "WROTE PAYLOAD stat=%d", (int) stat);

	    msg (D_LOW, "COMMON NAME: %s", tls_common_name (c->c2.tls_multi));
	  }
#endif
#endif

	  event_timeout_clear (&c->c2.wait_for_connect);
	}
    }
}

/*
 * Add routes.
 */
void
check_add_routes_dowork (struct context *c)
{
  do_route (&c->options, &c->c1.route_list);
  c->c2.current = time (NULL);
  event_timeout_clear (&c->c2.route_wakeup);
}

/*
 * Should we exit due to inactivity timeout?
 */
void
check_inactivity_timeout_dowork (struct context *c)
{
  msg (M_INFO, "Inactivity timeout (--inactive), exiting");
  c->sig->signal_received = SIGTERM;
  c->sig->signal_text = "inactive";
}

/*
 * Should we deliver a datagram fragment to remote?
 */
void
check_fragment_dowork (struct context *c)
{
  /* OS MTU Hint? */
  if (c->c2.link_socket.mtu_changed && c->c2.ipv4_tun)
    {
      frame_adjust_path_mtu (&c->c2.frame_fragment, c->c2.link_socket.mtu,
			     c->options.proto);
      c->c2.link_socket.mtu_changed = false;
    }

  if (!c->c2.to_link.len
      && fragment_outgoing_defined (c->c2.fragment)
      && fragment_ready_to_send (c->c2.fragment, &c->c2.buf,
				 &c->c2.frame_fragment))
    encrypt_sign (c, false);

  fragment_housekeeping (c->c2.fragment, &c->c2.frame_fragment, c->c2.current,
			 &c->c2.timeval);
}

/*
 * Compress, fragment, encrypt and HMAC-sign an outgoing packet.
 */
void
encrypt_sign (struct context *c, bool comp_frag)
{
  if (comp_frag)
    {
#ifdef USE_LZO
      /* Compress the packet. */
      if (c->options.comp_lzo)
	lzo_compress (&c->c2.buf, c->c2.lzo_compress_buf, &c->c2.lzo_compwork,
		      &c->c2.frame, c->c2.current);
#endif
      if (c->c2.fragment)
	fragment_outgoing (c->c2.fragment, &c->c2.buf, &c->c2.frame_fragment,
			   c->c2.current);
    }

#ifdef USE_CRYPTO
#ifdef USE_SSL
  /*
   * If TLS mode, get the key we will use to encrypt
   * the packet.
   */
  mutex_lock (L_TLS);
  if (c->c2.tls_multi)
    tls_pre_encrypt (c->c2.tls_multi, &c->c2.buf, &c->c2.crypto_options);
#endif

  /*
   * Encrypt the packet and write an optional
   * HMAC signature.
   */
  openvpn_encrypt (&c->c2.buf, c->c2.encrypt_buf, &c->c2.crypto_options,
		   &c->c2.frame, c->c2.current);
#endif
  /*
   * Get the address we will be sending the packet to.
   */
  link_socket_get_outgoing_addr (&c->c2.buf, &c->c2.link_socket,
				 &c->c2.to_link_addr);
#ifdef USE_CRYPTO
#ifdef USE_SSL
  /*
   * In TLS mode, prepend the appropriate one-byte opcode
   * to the packet which identifies it as a data channel
   * packet and gives the low-permutation version of
   * the key-id to the recipient so it knows which
   * decrypt key to use.
   */
  if (c->c2.tls_multi)
    tls_post_encrypt (c->c2.tls_multi, &c->c2.buf);
  mutex_unlock (L_TLS);
#endif
#endif
  c->c2.to_link = c->c2.buf;
  c->c2.free_to_link = false;
}

void
pre_select (struct context *c)
{
  /* make sure current time (c->c2.current) is updated on function entry */

  /*
   * Start with an effectively infinite timeout, then let it
   * reduce to a timeout that reflects the component which
   * needs the earliest service.
   */
  c->c2.timeval.tv_sec = BIG_TIMEOUT;
  c->c2.timeval.tv_usec = 0;

#if defined(WIN32) && defined(TAP_WIN32_DEBUG)
  c->c2.timeval.tv_sec = 1;
  if (check_debug_level (D_TAP_WIN32_DEBUG))
    tun_show_debug (&c->c1.tuntap);
#endif

#ifdef USE_CRYPTO
  /* flush current packet-id to file once per 60
     seconds if --replay-persist was specified */
  packet_id_persist_flush (&c->c1.pid_persist, c->c2.current, 60);
#endif

  /* Does TLS need service? */
  check_tls (c);

  /* In certain cases, TLS errors will require a restart */
  check_tls_errors (c);
  if (c->sig->signal_received)
    return;

  /* check for incoming configuration info on the control channel */
  check_incoming_control_channel (c);

  /* process connection establishment items */
  check_connection_established (c);

  /* process --route options */
  check_add_routes (c);

  /* possibly exit due to --inactive */
  check_inactivity_timeout (c);
  if (c->sig->signal_received)
    return;

  /* restart if ping not received */
  check_ping_restart (c);
  if (c->sig->signal_received)
    return;

  /* Should we send an OCC_REQUEST message? */
  check_send_occ_req (c);

  /* Should we send an MTU load test? */
  check_send_occ_load_test (c);

  /* Should we send an OCC message? */
  check_send_occ_msg (c);

  /* Should we deliver a datagram fragment to remote? */
  check_fragment (c);

  /* Should we ping the remote? */
  check_ping_send (c);

  /* caller should do garbage collect after this function returns */
}

void
single_select (struct context *c)
{
  /*
   * Set up for select call.
   *
   * Decide what kind of events we want to wait for.
   */
  wait_reset (&c->c2.event_wait);

  /*
   * On win32 we use the keyboard or an event object as a source
   * of asynchronous signals.
   */
  WAIT_SIGNAL (&c->c2.event_wait);

  /*
   * If outgoing data (for TCP/UDP port) pending, wait for ready-to-send
   * status from TCP/UDP port. Otherwise, wait for incoming data on
   * TUN/TAP device.
   */
  if (c->c2.to_link.len > 0)
    {
      /*
       * If sending this packet would put us over our traffic shaping
       * quota, don't send -- instead compute the delay we must wait
       * until it will be OK to send the packet.
       */

#ifdef HAVE_GETTIMEOFDAY
      int delay = 0;

      /* set traffic shaping delay in microseconds */
      if (c->options.shaper)
	delay = max_int (delay, shaper_delay (&c->c2.shaper));

      if (delay < 1000)
	{
	  SOCKET_SET_WRITE (&c->c2.event_wait, &c->c2.link_socket);
	}
      else
	{
	  shaper_soonest_event (&c->c2.timeval, delay);
	}
#else /* HAVE_GETTIMEOFDAY */
      SOCKET_SET_WRITE (&c->c2.event_wait, &c->c2.link_socket);
#endif /* HAVE_GETTIMEOFDAY */
    }
  else if (!c->c2.fragment || !fragment_outgoing_defined (c->c2.fragment))
    {
      TUNTAP_SET_READ (&c->c2.event_wait, &c->c1.tuntap);
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
      if (c->options.tls_thread)
	{
	  TLS_THREAD_SOCKET_SET (c->c2.tls_multi, &c->c2.event_wait,
				 &c->c2.thread_parms, reads);
	}
#endif
    }

  /*
   * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
   * from device.  Otherwise, wait for incoming data on TCP/UDP port.
   */
  if (c->c2.to_tun.len > 0)
    {
      TUNTAP_SET_WRITE (&c->c2.event_wait, &c->c1.tuntap);
    }
  else
    {
      SOCKET_SET_READ (&c->c2.event_wait, &c->c2.link_socket);
    }

  /*
   * Possible scenarios:
   *  (1) tcp/udp port has data available to read
   *  (2) tcp/udp port is ready to accept more data to write
   *  (3) tun dev has data available to read
   *  (4) tun dev is ready to accept more data to write
   *  (5) tls background thread has data available to forward to
   *      tcp/udp port
   *  (6) we received a signal (handler sets signal_received)
   *  (7) timeout (tv) expired (from TLS, shaper, inactivity
   *      timeout, or ping timeout)
   */

  /*
   * Wait for something to happen.
   */
  c->c2.select_status = 1;	/* this will be our return "status" if select doesn't get called */
  if (!c->sig->signal_received && !SOCKET_READ_RESIDUAL (&c->c2.link_socket))
    {
      if (check_debug_level (D_SELECT))
	show_select_status (c);
      c->c2.select_status = SELECT (&c->c2.event_wait, &c->c2.timeval);
      check_status (c->c2.select_status, "select", NULL, NULL);
    }

  /* current should always be a reasonably up-to-date timestamp */
  c->c2.current = time (NULL);

  /* set signal_received if a signal was received */
  SELECT_SIGNAL_RECEIVED (&c->c2.event_wait, c->sig->signal_received);
}

/*
 * Handle addition and removal of the 10-byte Socks5 header
 * in UDP packets.
 */

static inline void
socks_postprocess_incoming_link (struct context *c)
{
  if (c->c2.link_socket.socks_proxy && c->c2.link_socket.proto == PROTO_UDPv4)
    socks_process_incoming_udp (&c->c2.buf, &c->c2.from);
}

static inline void
socks_preprocess_outgoing_link (struct context *c,
				struct sockaddr_in **to_addr,
				int *size_delta)
{
  if (c->c2.link_socket.socks_proxy && c->c2.link_socket.proto == PROTO_UDPv4)
    {
      *size_delta += socks_process_outgoing_udp (&c->c2.to_link, &c->c2.to_link_addr);
      *to_addr = &c->c2.link_socket.socks_relay;
    }
}

/* undo effect of socks_preprocess_outgoing_link */
static inline void
link_socket_write_post_size_adjust (int *size,
				    int size_delta,
				    struct buffer *buf)
{
  if (size_delta > 0 && *size > size_delta)
    {
      *size -= size_delta;
      if (!buf_advance (buf, size_delta))
	*size = 0;
    }
}

void
read_incoming_link (struct context *c)
{
  /*
   * Set up for recvfrom call to read datagram
   * sent to our TCP/UDP port.
   */
  int status;

  ASSERT (!c->c2.to_tun.len);

  c->c2.buf = c->c2.read_link_buf;
  ASSERT (buf_init (&c->c2.buf, FRAME_HEADROOM (&c->c2.frame)));
  status = link_socket_read (&c->c2.link_socket, &c->c2.buf, MAX_RW_SIZE_LINK (&c->c2.frame), &c->c2.from);

  if (socket_connection_reset (&c->c2.link_socket, status))
    {
      /* received a disconnect from a connection-oriented protocol */
      if (c->options.inetd)
	{
	  c->sig->signal_received = SIGTERM;
	  msg (D_STREAM_ERRORS, "Connection reset, inetd/xinetd exit [%d]", status);
	}
      else
	{
	  c->sig->signal_received = SIGUSR1;
	  msg (D_STREAM_ERRORS, "Connection reset, restarting [%d]", status);
	}
      c->sig->signal_text = "connection-reset";
      return;
    }

  /* check recvfrom status */
  check_status (status, "read", &c->c2.link_socket, NULL);

  /* Remove socks header if applicable */
  socks_postprocess_incoming_link (c);
}

void
process_incoming_link (struct context *c)
{
  if (c->c2.buf.len > 0)
    {
      c->c2.link_read_bytes += c->c2.buf.len;
      c->c2.original_recv_size = c->c2.buf.len;
    }
  else
    c->c2.original_recv_size = 0;

  /* take action to corrupt packet if we are in gremlin test mode */
  if (c->options.gremlin) {
    if (!ask_gremlin())
      c->c2.buf.len = 0;
    corrupt_gremlin (&c->c2.buf);
  }

  /* log incoming packet */
#ifdef LOG_RW
  if (c->c2.log_rw)
    fprintf (stderr, "R");
#endif
  msg (D_LINK_RW, "%s READ [%d] from %s: %s",
       proto2ascii (c->c2.link_socket.proto, true),
       BLEN (&c->c2.buf),
       print_sockaddr (&c->c2.from),
       PROTO_DUMP (&c->c2.buf));

  /*
   * Good, non-zero length packet received.
   * Commence multi-stage processing of packet,
   * such as authenticate, decrypt, decompress.
   * If any stage fails, it sets buf.len to 0 or -1,
   * telling downstream stages to ignore the packet.
   */
  if (c->c2.buf.len > 0)
    {
      link_socket_incoming_addr (&c->c2.buf, &c->c2.link_socket, &c->c2.from);
#ifdef USE_CRYPTO
#ifdef USE_SSL
      mutex_lock (L_TLS);
      if (c->c2.tls_multi)
	{
	  /*
	   * If tls_pre_decrypt returns true, it means the incoming
	   * packet was a good TLS control channel packet.  If so, TLS code
	   * will deal with the packet and set buf.len to 0 so downstream
	   * stages ignore it.
	   *
	   * If the packet is a data channel packet, tls_pre_decrypt
	   * will load crypto_options with the correct encryption key
	   * and return false.
	   */
	  if (tls_pre_decrypt (c->c2.tls_multi, &c->c2.from, &c->c2.buf, &c->c2.crypto_options, c->c2.current))
	    {
#ifdef USE_PTHREAD
	      if (c->options.tls_thread)
		{
		  /* tell TLS thread a packet is waiting */
		  if (tls_thread_process (&c->c2.thread_parms) == -1)
		    {
		      msg (M_WARN, "TLS thread is not responding, exiting (1)");
		      c->sig->signal_received = 0;
		      c->sig->signal_text = "error";
		      mutex_unlock (L_TLS);
		      return;
		    }
		}
	      else
#endif
		{
		  interval_action (&c->c2.tmp_int, c->c2.current);
		}

	      /* reset packet received timer if TLS packet */
	      if (c->options.ping_rec_timeout)
		event_timeout_reset (&c->c2.ping_rec_interval, c->c2.current);
	    }
	}
#endif /* USE_SSL */
      /* authenticate and decrypt the incoming packet */
      if (!openvpn_decrypt (&c->c2.buf, c->c2.decrypt_buf, &c->c2.crypto_options, &c->c2.frame, c->c2.current))
	{
	  if (link_socket_connection_oriented (&c->c2.link_socket))
	    {
	      /* decryption errors are fatal in TCP mode */
	      c->sig->signal_received = SIGUSR1;
	      msg (D_STREAM_ERRORS, "Fatal decryption error, restarting");
	      c->sig->signal_text = "decryption-error";
	      mutex_unlock (L_TLS);
	      return;
	    }
	}
#ifdef USE_SSL
      mutex_unlock (L_TLS);
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
      if (c->c2.fragment)
	fragment_incoming (c->c2.fragment, &c->c2.buf, &c->c2.frame_fragment, c->c2.current);
#ifdef USE_LZO
      /* decompress the incoming packet */
      if (c->options.comp_lzo)
	lzo_decompress (&c->c2.buf, c->c2.lzo_decompress_buf, &c->c2.lzo_compwork, &c->c2.frame);
#endif
      /*
       * Set our "official" outgoing address, since
       * if buf.len is non-zero, we know the packet
       * authenticated.  In TLS mode we do nothing
       * because TLS mode takes care of source address
       * authentication.
       *
       * Also, update the persisted version of our packet-id.
       */
      if (!TLS_MODE)
	link_socket_set_outgoing_addr (&c->c2.buf, &c->c2.link_socket, &c->c2.from);

      /* reset packet received timer */
      if (c->options.ping_rec_timeout && c->c2.buf.len > 0)
	event_timeout_reset (&c->c2.ping_rec_interval, c->c2.current);

      /* increment authenticated receive byte count */
      if (c->c2.buf.len > 0)
	{
	  c->c2.link_read_bytes_auth += c->c2.buf.len;
	  c->c2.max_recv_size_local = max_int (c->c2.original_recv_size, c->c2.max_recv_size_local);
	}

      /* Did we just receive an openvpn ping packet? */
      if (is_ping_msg (&c->c2.buf))
	{
	  msg (D_PACKET_CONTENT, "RECEIVED PING PACKET");
	  c->c2.buf.len = 0; /* drop packet */
	}

      /* Did we just receive an OCC packet? */
      if (is_occ_msg (&c->c2.buf))
	process_received_occ_msg (c);
      
      c->c2.to_tun = c->c2.buf;
    }
  else
    {
      c->c2.to_tun = c->c2.nullbuf;
    }
}

void
read_incoming_tun (struct context *c)
{
  /*
   * Setup for read() call on TUN/TAP device.
   */
  ASSERT (!c->c2.to_link.len);

  c->c2.buf = c->c2.read_tun_buf;
#ifdef TUN_PASS_BUFFER
  read_tun_buffered (&c->c1.tuntap, &c->c2.buf, MAX_RW_SIZE_TUN (&c->c2.frame));
#else
  ASSERT (buf_init (&c->c2.buf, FRAME_HEADROOM (&c->c2.frame)));
  ASSERT (buf_safe (&c->c2.buf, MAX_RW_SIZE_TUN (&c->c2.frame)));
  c->c2.buf.len = read_tun (&c->c1.tuntap, BPTR (&c->c2.buf), MAX_RW_SIZE_TUN (&c->c2.frame));
#endif

  /* Was TUN/TAP interface stopped? */
  if (tuntap_stop (c->c2.buf.len))
    {
      c->sig->signal_received = SIGTERM;
      c->sig->signal_text = "tun-stop";
      msg (M_INFO, "TUN/TAP interface has been stopped, exiting");
      return;		  
    }

  /* Check the status return from read() */
  check_status (c->c2.buf.len, "read from TUN/TAP", NULL, &c->c1.tuntap);
}

void
process_incoming_tun (struct context *c)
{
  if (c->c2.buf.len > 0)
    c->c2.tun_read_bytes += c->c2.buf.len;

#ifdef LOG_RW
  if (c->c2.log_rw)
    fprintf (stderr, "r");
#endif

  /* Show packet content */
  msg (D_TUN_RW, "TUN READ [%d]: %s md5=%s",
       BLEN (&c->c2.buf),
       format_hex (BPTR (&c->c2.buf), BLEN (&c->c2.buf), 80),
       MD5SUM (BPTR (&c->c2.buf), BLEN (&c->c2.buf)));

  if (c->c2.buf.len > 0)
    {
      /*
       * The --passtos and --mssfix options require
       * us to examine the IPv4 header.
       */
      if (c->options.mssfix_defined
#if PASSTOS_CAPABILITY
	  || c->options.passtos
#endif
	  )
	{
	  struct buffer ipbuf = c->c2.buf;
	  if (is_ipv4 (TUNNEL_TYPE (&c->c1.tuntap), &ipbuf))
	    {
#if PASSTOS_CAPABILITY
	      /* extract TOS from IP header */
	      if (c->options.passtos)
		{
		  struct openvpn_iphdr *iph = 
		    (struct openvpn_iphdr *) BPTR (&ipbuf);
		  c->c2.ptos = iph->tos;
		  c->c2.ptos_defined = true;
		}
#endif
			  
	      /* possibly alter the TCP MSS */
	      if (c->options.mssfix_defined)
		mss_fixup (&ipbuf, MTU_TO_MSS (TUN_MTU_SIZE_DYNAMIC (&c->c2.frame)));
	    }
	}
      encrypt_sign (c, true);
    }
  else
    {
      c->c2.to_link = c->c2.nullbuf;
      c->c2.free_to_link = false;
    }
}

void
process_outgoing_link (struct context *c, struct link_socket *ls)
{
  if (c->c2.to_link.len > 0 && c->c2.to_link.len <= EXPANDED_SIZE (&c->c2.frame))
    {
      /*
       * Setup for call to send/sendto which will send
       * packet to remote over the TCP/UDP port.
       */
      int size;
      ASSERT (addr_defined (&c->c2.to_link_addr));

      /* In gremlin-test mode, we may choose to drop this packet */
      if (!c->options.gremlin || ask_gremlin())
	{
	  /*
	   * Let the traffic shaper know how many bytes
	   * we wrote.
	   */
#ifdef HAVE_GETTIMEOFDAY
	  if (c->options.shaper)
	    shaper_wrote_bytes (&c->c2.shaper, BLEN (&c->c2.to_link)
				+ datagram_overhead (c->options.proto));
#endif
	  /*
	   * Let the pinger know that we sent a packet.
	   */
	  if (c->options.ping_send_timeout)
	    event_timeout_reset (&c->c2.ping_send_interval, c->c2.current);

#if PASSTOS_CAPABILITY
	  /* Set TOS */
	  if (c->c2.ptos_defined)
	    setsockopt (ls->sd, IPPROTO_IP, IP_TOS, &c->c2.ptos, sizeof (c->c2.ptos));
#endif

	  /* Log packet send */
#ifdef LOG_RW
	  if (c->c2.log_rw)
	    fprintf (stderr, "W");
#endif
	  msg (D_LINK_RW, "%s WRITE [%d] to %s: %s",
	       proto2ascii (ls->proto, true),
	       BLEN (&c->c2.to_link),
	       print_sockaddr (&c->c2.to_link_addr),
	       PROTO_DUMP (&c->c2.to_link));

	  /* Packet send complexified by possible Socks5 usage */
	  {
	    struct sockaddr_in *to_addr = &c->c2.to_link_addr;
	    int size_delta = 0;

	    /* If Socks5 over UDP, prepend header */
	    socks_preprocess_outgoing_link (c, &to_addr, &size_delta);

	    /* Send packet */
	    size = link_socket_write (ls, &c->c2.to_link, to_addr);

	    /* Undo effect of prepend */
	    link_socket_write_post_size_adjust (&size, size_delta, &c->c2.to_link);
	  }

	  if (size > 0)
	    {
	      c->c2.max_send_size_local = max_int (size, c->c2.max_send_size_local);
	      c->c2.link_write_bytes += size;
	    }
	}
      else
	size = 0;

      /* Check return status */
      check_status (size, "write", ls, NULL);

      if (size > 0)
	{
	  /* Did we write a different size packet than we intended? */
	  if (size != BLEN (&c->c2.to_link))
	    msg (D_LINK_ERRORS,
		 "TCP/UDP packet was truncated/expanded on write to %s (tried=%d,actual=%d)",
		 print_sockaddr (&c->c2.to_link_addr),
		 BLEN (&c->c2.to_link),
		 size);
	}
    }
  else
    {
      msg (D_LINK_ERRORS, "TCP/UDP packet too large on write to %s (tried=%d,max=%d)",
	   print_sockaddr (&c->c2.to_link_addr),
	   c->c2.to_link.len,
	   EXPANDED_SIZE (&c->c2.frame));
    }

  /*
   * The free_to_link flag means that we should free the packet buffer
   * after send.  This flag is usually set when the TLS background
   * thread generated the packet buffer.
   */
  if (c->c2.free_to_link)
    {
      c->c2.free_to_link = false;
      free_buf (&c->c2.to_link);
    }
  c->c2.to_link = c->c2.nullbuf;
}

void
process_outgoing_tun (struct context *c, struct tuntap *tt)
{
  /*
   * Set up for write() call to TUN/TAP
   * device.
   */
  ASSERT (c->c2.to_tun.len > 0);

  /*
   * The --mssfix option requires
   * us to examine the IPv4 header.
   */
  if (c->options.mssfix_defined)
    {
      struct buffer ipbuf = c->c2.to_tun;

      if (is_ipv4 (tt->type, &ipbuf))
	{
	  /* possibly alter the TCP MSS */
	  if (c->options.mssfix_defined)
	    mss_fixup (&ipbuf, MTU_TO_MSS (TUN_MTU_SIZE_DYNAMIC (&c->c2.frame)));
	}
    }
	      
  if (c->c2.to_tun.len <= MAX_RW_SIZE_TUN (&c->c2.frame))
    {
      /*
       * Write to TUN/TAP device.
       */
      int size;

#ifdef LOG_RW
      if (c->c2.log_rw)
	fprintf (stderr, "w");
#endif
      msg (D_TUN_RW, "TUN WRITE [%d]: %s md5=%s",
	   BLEN (&c->c2.to_tun),
	   format_hex (BPTR (&c->c2.to_tun), BLEN (&c->c2.to_tun), 80),
	   MD5SUM (BPTR (&c->c2.to_tun), BLEN (&c->c2.to_tun)));

#ifdef TUN_PASS_BUFFER
      size = write_tun_buffered (tt, &c->c2.to_tun);
#else
      size = write_tun (tt, BPTR (&c->c2.to_tun), BLEN (&c->c2.to_tun));
#endif

      if (size > 0)
	c->c2.tun_write_bytes += size;
      check_status (size, "write to TUN/TAP", NULL, tt);

      /* check written packet size */
      if (size > 0)
	{
	  /* Did we write a different size packet than we intended? */
	  if (size != BLEN (&c->c2.to_tun))
	    msg (D_LINK_ERRORS,
		 "TUN/TAP packet was fragmented on write to %s (tried=%d,actual=%d)",
		 tt->actual,
		 BLEN (&c->c2.to_tun),
		 size);
	}
    }
  else
    {
      /*
       * This should never happen, probably indicates some kind
       * of MTU mismatch.
       */
      msg (D_LINK_ERRORS, "tun packet too large on write (tried=%d,max=%d)",
	   c->c2.to_tun.len,
	   MAX_RW_SIZE_TUN (&c->c2.frame));
    }

  /*
   * Putting the --inactive timeout reset here, ensures that we will timeout
   * if the remote goes away, even if we are trying to send data to the
   * remote and failing.
   */
  if (c->options.inactivity_timeout)
    event_timeout_reset (&c->c2.inactivity_interval, c->c2.current);

  c->c2.to_tun = c->c2.nullbuf;
}

#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
void
process_incoming_tls_thread (struct context *c)
{
  int s;
  ASSERT (!c->c2.to_link.len);

  s = tls_thread_rec_buf (&c->c2.thread_parms, &c->c2.tt_ret, true);
  if (s == 1)
    {
      /*
       * TLS background thread has a control channel
       * packet to send to remote.
       */
      c->c2.to_link = c->c2.tt_ret.to_link;
      c->c2.to_link_addr = c->c2.tt_ret.to_link_addr;
      
      /* tell TCP/UDP packet writer to free buffer after write */
      c->c2.free_to_link = true;
    }
  
  /* remote died? */
  else if (s == -1)
    {
      msg (M_WARN, "TLS thread is not responding, exiting (2)");
      c->sig->signal_received = 0;
      c->sig->signal_text = "error";
    }
}
#endif

void
process_io (struct context *c)
{
  if (c->c2.select_status > 0)
    {
      /* Incoming data on TCP/UDP port */
      if (SOCKET_READ_RESIDUAL (&c->c2.link_socket) || SOCKET_ISSET (&c->c2.event_wait, &c->c2.link_socket, reads))
	{
	  read_incoming_link (c);
	  if (!IS_SIG (c))
	    process_incoming_link (c);
	}
      /* Incoming data on TUN device */
      else if (TUNTAP_ISSET (&c->c2.event_wait, &c->c1.tuntap, reads))
	{
	  read_incoming_tun (c);
	  if (!IS_SIG (c))
	    process_incoming_tun (c);
	}
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
      /* Incoming data from TLS background thread */
      else if (c->options.tls_thread && TLS_THREAD_SOCKET_ISSET (c->c2.tls_multi, &c->c2.event_wait, &c->c2.thread_parms, reads))
	{
	  process_incoming_tls_thread (c);
	}
#endif
      /* TCP/UDP port ready to accept write */
      else if (SOCKET_ISSET (&c->c2.event_wait, &c->c2.link_socket, writes))
	{
	  process_outgoing_link (c, &c->c2.link_socket);
	}
      /* TUN device ready to accept write */
      else if (TUNTAP_ISSET (&c->c2.event_wait, &c->c1.tuntap, writes))
	{
	  process_outgoing_tun (c, &c->c1.tuntap);
	}
    }
}
