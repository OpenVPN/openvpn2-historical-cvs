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

#ifndef FORWARD_INLINE_H
#define FORWARD_INLINE_H

/*
 * Inline functions
 */

/*
 * Does TLS session need service?
 */
static inline void
check_tls (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  void check_tls_dowork (struct context *c);
  if (c->c2.tls_multi
#if defined(USE_PTHREAD)
      && !c->options.tls_thread
#endif
    )
    check_tls_dowork (c);
#endif
}

/*
 * TLS errors are fatal in TCP mode
 */
static inline void
check_tls_errors (struct context *c)
{
#if defined(USE_CRYPTO) && defined(USE_SSL)
  void check_tls_errors_dowork (struct context *c);
  if (c->c2.tls_multi && link_socket_connection_oriented (&c->c2.link_socket)
      && c->c2.tls_multi->n_errors)
    check_tls_errors_dowork (c);
#endif
}

/*
 * Options like --up-delay need to be triggered by this function which
 * checks for connection establishment.
 */
static inline void
check_connection_established (struct context *c)
{
  void check_connection_established_dowork (struct context *c);
  if (event_timeout_defined (&c->c2.wait_for_connect))
    check_connection_established_dowork (c);
}

/*
 * Should we add routes?
 */
static inline void
check_add_routes (struct context *c)
{
  static void check_add_routes_dowork (struct context *c);
  if (event_timeout_trigger
      (&c->c2.route_wakeup, c->c2.current, &c->c2.timeval))
    check_add_routes_dowork (c);
}

/*
 * Should we exit due to inactivity timeout?
 */
static inline void
check_inactivity_timeout (struct context *c)
{
  void check_inactivity_timeout_dowork (struct context *c);
  if (c->options.inactivity_timeout
      && event_timeout_trigger (&c->c2.inactivity_interval, c->c2.current,
				&c->c2.timeval))
    check_inactivity_timeout_dowork (c);
}

/*
 * Should we deliver a datagram fragment to remote?
 */
static inline void
check_fragment (struct context *c)
{
  void check_fragment_dowork (struct context *c);
  if (c->c2.fragment)
    check_fragment_dowork (c);
}

#endif /* EVENT_INLINE_H */
