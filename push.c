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

#include "options.h"
#include "push.h"

#include "memdbg.h"

#if P2MP

bool
send_push_request (struct context *c)
{
  return send_control_channel_string (c, "PUSH_REQUEST");
}

bool
send_push_reply (struct context *c)
{
  struct gc_arena gc = gc_new ();
  struct buffer buf = alloc_buf_gc (MAX_PUSH_LIST_LEN + 256, &gc);
  bool ret;

  buf_printf (&buf, "PUSH_REPLY");

  if (c->options.push_list && strlen (c->options.push_list->options))
    buf_printf (&buf, ",%s", c->options.push_list->options);

  if (c->c2.push_ifconfig_local && c->c2.push_ifconfig_remote)
    buf_printf (&buf, ",ifconfig %s %s",
		print_in_addr_t (c->c2.push_ifconfig_local, true, &gc),
		print_in_addr_t (c->c2.push_ifconfig_remote, true, &gc));

  if (strlen (BSTR (&buf)) >= MAX_PUSH_LIST_LEN)
    msg (M_FATAL, "Maximum length of --push buffer (%d) has been exceeded", MAX_PUSH_LIST_LEN);

  ret = send_control_channel_string (c, BSTR (&buf));

  gc_free (&gc);
  return ret;
}

void
push_option (struct options *o, const char *opt)
{
  int len;
  bool first = false;
  if (!o->push_list)
    {
      o->push_list = (struct push_list *) gc_malloc (sizeof (struct push_list), true, &o->gc);
      first = true;
    }

  len = strlen (o->push_list->options);
  if (len + strlen (opt) + 2 >= MAX_PUSH_LIST_LEN)
    msg (M_USAGE, "Maximum length of --push buffer (%d) has been exceeded", MAX_PUSH_LIST_LEN);
  if (!first)
    strcat (o->push_list->options, ",");
  strcat (o->push_list->options, opt);
}

bool
process_incoming_push_msg (struct context *c, struct buffer *buf)
{
  bool ret = false;
  if (buf_string_compare_advance (buf, "PUSH_REQUEST"))
    {
      ret = send_push_reply (c);
    }
  else if (buf_string_compare_advance (buf, "PUSH_REPLY,"))
    {
      ret = apply_push_options (&c->options, buf);
      show_settings (&c->options); // JYFIXME
    }
  return ret;
}

#endif
