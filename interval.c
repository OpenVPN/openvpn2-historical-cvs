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

#include "interval.h"

#include "memdbg.h"

void
interval_init (struct interval *top, int horizon, int refresh)
{
  CLEAR (*top);
  top->refresh = refresh;
  top->horizon = horizon;
}

bool
event_timeout_trigger (struct event_timeout *et,
		       struct timeval *tv,
		       const int et_const_retry)
{
  bool ret = false;
  const time_t local_now = now;

  if (et->defined)
    {
      int wakeup = (int) et->last + et->n - local_now;
      if (wakeup <= 0)
	{
#if INTERVAL_DEBUG
	  msg (D_INTERVAL, "EVENT event_timeout_trigger (%d) etcr=%d", et->n, et_const_retry);
#endif
	  if (et_const_retry < 0)
	    {
	      et->last = local_now;
	      wakeup = et->n;
	      ret = true;
	    }
	  else
	    {
	      wakeup = et_const_retry;
	    }
	}

      if (wakeup < tv->tv_sec)
	{
#if INTERVAL_DEBUG
	  msg (D_INTERVAL, "EVENT event_timeout_wakeup (%d/%d) etcr=%d", wakeup, et->n, et_const_retry);
#endif
	  tv->tv_sec = wakeup;
	  tv->tv_usec = 0;
	}
    }
  return ret;
}
