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

#include "status.h"

#include "memdbg.h"

/*
 * printf-style interface for outputting status info
 */

struct status_output *
status_open (const char *filename, int refresh_freq, int msglevel)
{
  struct status_output *so = NULL;
  if (filename || msglevel >= 0)
    {
      ALLOC_OBJ_CLEAR (so, struct status_output);
      so->msglevel = msglevel;
      so->fd = -1;
      if (filename)
	{
	  so->fd = open (filename,
			 O_CREAT | O_TRUNC | O_WRONLY,
			 S_IRUSR | S_IWUSR);
	  if (so->fd >= 0)
	    so->filename = string_alloc (filename, NULL);
	  else
	    msg (M_WARN, "Note: cannot open %s for status info output", filename);
	}
      if (refresh_freq > 0)
	{
	  event_timeout_init (&so->et, refresh_freq, 0);
	}
    }
  return so;
}

bool
status_trigger (struct status_output *so)
{
  struct timeval null;
  CLEAR (null);
  return event_timeout_trigger (&so->et, &null, ETT_DEFAULT);
}

bool
status_trigger_tv (struct status_output *so, struct timeval *tv)
{
  return event_timeout_trigger (&so->et, tv, ETT_DEFAULT);
}

void
status_reset (struct status_output *so)
{
  if (so && so->fd >= 0)
    lseek (so->fd, (off_t)0, SEEK_SET);
}

void
status_flush (struct status_output *so)
{
  if (so && so->fd >= 0)
    {
#if 0
      // test truncate
      {
	static int foo;
	if (foo++ & 1)
	  {
	    int i;
	    for (i = 0; i < 10; ++i)
	      status_printf (so, "[%d] LONG This is a test", i);
	  }
	else
	  status_printf (so, "[0] SHORT");
      }
#endif
#if defined(HAVE_FTRUNCATE)
      {
	const off_t off = lseek (so->fd, (off_t)0, SEEK_CUR);
	ftruncate (so->fd, off);
      }
#elif defined(HAVE_CHSIZE)
      {
	const long off = (long) lseek (so->fd, (off_t)0, SEEK_CUR);
	chsize (so->fd, off);
      }
#else
#warning both ftruncate and chsize functions appear to be missing from this OS
#endif
    }
}

void
status_close (struct status_output *so)
{
  if (so)
    {
      if (so->fd >= 0)
	close (so->fd);
      if (so->filename)
	free (so->filename);
      free (so);
    }
}

#define STATUS_PRINTF_MAXLEN 256

void
status_printf (struct status_output *so, const char *format, ...)
{
  if (so)
    {
      char buf[STATUS_PRINTF_MAXLEN+1]; /* leave extra byte for newline */
      va_list arglist;

      va_start (arglist, format);
      vsnprintf (buf, STATUS_PRINTF_MAXLEN, format, arglist);
      va_end (arglist);
      buf[STATUS_PRINTF_MAXLEN - 1] = 0;

      if (so->fd >= 0)
	{
	  int len;
	  strcat (buf, "\n");
	  len = strlen (buf);
	  if (len > 0)
	    write (so->fd, buf, len);
	}

      if (so->msglevel >= 0)
	msg (so->msglevel, "%s", buf);
    }
}
