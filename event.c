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
#include "integer.h"
#include "event.h"

#include "memdbg.h"

static inline int
tv_to_ms_timeout (const struct timeval *tv)
{
  return max_int (tv->tv_sec * 1000 + (tv->tv_usec + 500) / 1000, 1);
}

#ifdef WIN32

struct we_set
{
  struct event_set_functions func;
  bool fast;
  HANDLE *events;
  struct event_set_return *esr;
  int n_events;
  int capacity;
};

static void
we_free (struct event_set *es)
{
  struct we_set *wes = (struct we_set *) es;
  free (wes->events);
  free (wes->esr);
  free (wes);
}

static void
we_reset (struct event_set *es)
{
  struct we_set *wes = (struct we_set *) es;
  ASSERT (wes->fast);
  wes->n_events = 0;
}

static void
we_del (struct event_set *es, event_t event)
{
  struct we_set *wes = (struct we_set *) es;
  ASSERT (!wes->fast);
  ASSERT (0); // JYFIXME -- implement we_del
}

static void
we_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct we_set *wes = (struct we_set *) es;

  msg (D_EVENT_WAIT, "WE_CTL n=%d rwflags=0x%04x ev=0x%08x arg=0x%08x",
       wes->n_events,
       rwflags,
       (unsigned int)event,
       (unsigned int)arg);

  if (wes->fast)
    {
      if (rwflags & EVENT_WRITE)
	{
	  if (wes->n_events < wes->capacity)
	    {
	      wes->events[wes->n_events] = event->write;
	      wes->esr[wes->n_events].rwflags = EVENT_WRITE;
	      wes->esr[wes->n_events].arg = arg;
	      ++wes->n_events;
	    }
	  else
	    goto err;
	}
      if (rwflags & EVENT_READ)
	{
	  if (wes->n_events < wes->capacity)
	    {
	      wes->events[wes->n_events] = event->read;
	      wes->esr[wes->n_events].rwflags = EVENT_READ;
	      wes->esr[wes->n_events].arg = arg;
	      ++wes->n_events;
	    }
	  else
	    goto err;
	}
    }
  else
    {
      ASSERT (0); // JYFIXME -- implement we_ctl for !fast
    }
  return;

 err:
  msg (D_EVENT_ERRORS, "Error: Windows resource limit WSA_MAXIMUM_WAIT_EVENTS (%d) has been exceeded", WSA_MAXIMUM_WAIT_EVENTS);
}

static int
we_wait (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct we_set *wes = (struct we_set *) es;

  const DWORD status = WSAWaitForMultipleEvents(
    (DWORD) wes->n_events,
    wes->events,
    FALSE,
    (DWORD) tv_to_ms_timeout (tv),
    FALSE);
  
  if (outlen >= 1 && status >= WSA_WAIT_EVENT_0 && status < WSA_WAIT_EVENT_0 + (DWORD) wes->n_events)
    {
      *out = wes->esr[status - WSA_WAIT_EVENT_0];
      msg (D_EVENT_WAIT, "WE_WAIT rwflags=0x%04x arg=0x%08x",
	   out->rwflags, (unsigned int)out->arg);
      return 1;
    }
  else if (status == WSA_WAIT_TIMEOUT)
    return 0;
  else
    return -1;
}

static struct event_set *
we_init (int *maxevents, unsigned int flags)
{
  struct we_set *wes;
  ALLOC_OBJ_CLEAR (wes, struct we_set);

  /* set dispatch functions */
  wes->func.free = we_free;
  wes->func.reset = we_reset;
  wes->func.del = we_del;
  wes->func.ctl = we_ctl;
  wes->func.wait = we_wait;

  if (flags & EVENT_METHOD_FAST)
    wes->fast = true;
  wes->n_events = 0;

  /* Figure our event capacity */
  ASSERT (*maxevents > 0);
  wes->capacity = min_int (*maxevents * 2, WSA_MAXIMUM_WAIT_EVENTS);
  *maxevents = min_int (*maxevents, WSA_MAXIMUM_WAIT_EVENTS);

  /* Allocate space for Win32 event handles */
  ALLOC_ARRAY_CLEAR (wes->events, HANDLE, wes->capacity);

  /* Allocate space for event_set_return objects */
  ALLOC_ARRAY_CLEAR (wes->esr, struct event_set_return, wes->capacity);

  msg (D_EVENT_WAIT, "WE_INIT maxevents=%d capacity=%d",
       *maxevents, wes->capacity);

  return (struct event_set *) wes;
}

#endif /* WIN32 */

#if EPOLL

struct ep_set
{
  struct event_set_functions func;
  bool fast;
  int epfd;
  int maxevents;
  struct epoll_event *events;
};

static void
ep_free (struct event_set *es)
{
  struct ep_set *eps = (struct ep_set *) es;
  close (eps->epfd);
  free (eps->events);
  free (eps);
}

static void
ep_reset (struct event_set *es)
{
  const struct ep_set *eps = (struct ep_set *) es;
  ASSERT (eps->fast);
}

static void
ep_del (struct event_set *es, event_t event)
{
  struct ep_set *eps = (struct ep_set *) es;
  ASSERT (!eps->fast);
  if (epoll_ctl (eps->epfd, EPOLL_CTL_DEL, event, NULL) < 0)
    msg (M_ERR, "EVENT: epoll_ctl EPOLL_CTL_DEL failed");
}

static void
ep_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct ep_set *eps = (struct ep_set *) es;
  struct epoll_event ev;

  ev.events = 0;
  ev.data.ptr = arg;
  if (rwflags & EVENT_READ)
    ev.events |= EPOLLIN;
  if (rwflags & EVENT_WRITE)
    ev.events |= EPOLLOUT;
  msg (D_EVENT_WAIT, "EP_CTL fd=%d rwflags=0x%04x ev=0x%08x arg=0x%08x",
       (int)event, rwflags, ev.events, (unsigned int)ev.data.ptr);
  if (epoll_ctl (eps->epfd, EPOLL_CTL_MOD, event, &ev) < 0)
    {
      if (errno == ENOENT)
	{
	  if (epoll_ctl (eps->epfd, EPOLL_CTL_ADD, event, &ev) < 0)
	    msg (M_ERR, "EVENT: epoll_ctl EPOLL_CTL_ADD failed");
	}
      else
	msg (M_ERR, "EVENT: epoll_ctl EPOLL_CTL_MOD failed");
    }
}

static int
ep_wait (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct ep_set *eps = (struct ep_set *) es;
  int stat;

  if (outlen > eps->maxevents)
    outlen = eps->maxevents;

  stat = epoll_wait (eps->epfd, eps->events, outlen, tv_to_ms_timeout (tv));
  ASSERT (stat <= outlen);

  if (stat > 0)
    {
      int i;
      const struct epoll_event *ev = eps->events;
      struct event_set_return *esr = out;
      for (i = 0; i < stat; ++i)
	{
	  esr->rwflags = 0;
	  if (ev->events & (EPOLLIN|EPOLLPRI|EPOLLERR))
	    esr->rwflags |= EVENT_READ;
	  if (ev->events & EPOLLOUT)
	    esr->rwflags |= EVENT_WRITE;
	  esr->arg = ev->data.ptr;
	  msg (D_EVENT_WAIT, "EP_WAIT[%d] rwflags=0x%04x ev=0x%08x arg=0x%08x",
	       i, esr->rwflags, ev->events, (unsigned int)ev->data.ptr);
	  ++ev;
	  ++esr;
	}
    }
  return stat;
}

static struct event_set *
ep_init (int *maxevents, unsigned int flags)
{
  struct ep_set *eps;
  int fd;

  /* open epoll file descriptor */
  fd = epoll_create (*maxevents);
  if (fd < 0)
    return NULL;

  ALLOC_OBJ_CLEAR (eps, struct ep_set);

  /* set dispatch functions */
  eps->func.free = ep_free;
  eps->func.reset = ep_reset;
  eps->func.del = ep_del;
  eps->func.ctl = ep_ctl;
  eps->func.wait = ep_wait;

  /* fast method corresponds to epoll one-shot */
  if (flags & EVENT_METHOD_FAST)
    eps->fast = true;

  /* allocate space for epoll_wait return */
  ASSERT (*maxevents > 0);
  eps->maxevents = *maxevents;
  ALLOC_ARRAY_CLEAR (eps->events, struct epoll_event, eps->maxevents);

  /* set epoll control fd */
  eps->epfd = fd;

  return (struct event_set *) eps;
}
#endif /* EPOLL */

#if POLL

struct po_set
{
  struct event_set_functions func;
  bool fast;
  struct pollfd *events;
  void **args;
  int n_events;
  int capacity;
};

static void
po_free (struct event_set *es)
{
  struct po_set *pos = (struct po_set *) es;
  free (pos->events);
  free (pos->args);
  free (pos);
}

static void
po_reset (struct event_set *es)
{
  struct po_set *pos = (struct po_set *) es;
  ASSERT (pos->fast);
  pos->n_events = 0;
}

static void
po_del (struct event_set *es, event_t event)
{
  struct po_set *pos = (struct po_set *) es;
  ASSERT (!pos->fast);
  ASSERT (0); // JYFIXME -- implement po_del
}

static void
po_ctl (struct event_set *es, event_t event, unsigned int rwflags, void *arg)
{
  struct po_set *pos = (struct po_set *) es;

  msg (D_EVENT_WAIT, "PO_CTL rwflags=0x%04x ev=%d arg=0x%08x",
       rwflags, (unsigned int)event, (unsigned int)arg);

  if (pos->fast)
    {
      if (pos->n_events < pos->capacity)
	{
	  struct pollfd *pfdp = &pos->events[pos->n_events];
	  pfdp->fd = event;
	  pfdp->events = pfdp->revents = 0;
	  pos->args[pos->n_events] = arg;

	  if (rwflags & EVENT_WRITE)
	    pfdp->events |= POLLOUT;
	  if (rwflags & EVENT_READ)
	    pfdp->events |= (POLLIN|POLLPRI);

	  ++pos->n_events;
	}
      else
	goto err;
    }
  else
    {
      ASSERT (0); // JYFIXME -- implement po_ctl for !fast
    }
  return;

 err:
  msg (D_EVENT_ERRORS, "Error: poll: too many I/O wait events");
}

static int
po_wait (struct event_set *es, const struct timeval *tv, struct event_set_return *out, int outlen)
{
  struct po_set *pos = (struct po_set *) es;
  int stat;

  stat = poll (pos->events, pos->n_events, tv_to_ms_timeout (tv));
  ASSERT (stat <= pos->n_events);

  if (stat > 0)
    {
      int i, j=0;
      const struct pollfd *pfdp = pos->events;
      for (i = 0; i < pos->n_events && j < outlen; ++i)
	{
	  if (pfdp->revents & (POLLIN|POLLPRI|POLLERR|POLLHUP|POLLOUT))
	    {
	      out->rwflags = 0;
	      if (pfdp->revents & (POLLIN|POLLPRI|POLLERR|POLLHUP))
		out->rwflags |= EVENT_READ;
	      if (pfdp->revents & POLLOUT)
		out->rwflags |= EVENT_WRITE;
	      out->arg = pos->args[i];
	      msg (D_EVENT_WAIT, "PO_WAIT[%d,%d] fd=%d rev=0x%08x rwflags=0x%04x arg=0x%08x",
		   i, j, pfdp->fd, pfdp->revents, out->rwflags, (unsigned int)out->arg);
	      ++out;
	      ++j;
	    }
	  ++pfdp;
	}
      return j;
    }
  return stat;
}

static struct event_set *
po_init (int *maxevents, unsigned int flags)
{
  struct po_set *pos;
  ALLOC_OBJ_CLEAR (pos, struct po_set);

  /* set dispatch functions */
  pos->func.free = po_free;
  pos->func.reset = po_reset;
  pos->func.del = po_del;
  pos->func.ctl = po_ctl;
  pos->func.wait = po_wait;

  if (flags & EVENT_METHOD_FAST)
    pos->fast = true;

  pos->n_events = 0;

  /* Figure our event capacity */
  ASSERT (*maxevents > 0);
  pos->capacity = *maxevents;

  /* Allocate space for Win32 event handles */
  ALLOC_ARRAY_CLEAR (pos->events, struct pollfd, pos->capacity);

  /* Allocate space for event_set_return objects */
  ALLOC_ARRAY_CLEAR (pos->args, void *, pos->capacity);

  return (struct event_set *) pos;
}
#endif /* POLL */

struct event_set *
event_set_init (int *maxevents, unsigned int flags)
{
  struct event_set *ret = NULL;

#ifdef WIN32
  ret = we_init (maxevents, flags);
#else
#if EPOLL
  ret = ep_init (maxevents, flags);
  if (!ret)
    {
      msg (M_WARN, "Note: sys_epoll API is unavailable, falling back to poll API");
      ret = po_init (maxevents, flags);
    }
#elif POLL
  ret = po_init (maxevents, flags);
#else
#error At least one of epoll, poll, or WSAWaitForMultipleEvents must be supported by the kernel
#endif
#endif

  ASSERT (ret);
  return ret;
}
