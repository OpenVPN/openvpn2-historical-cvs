/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef THREAD_H
#define THREAD_H

#include "basic.h"
#include "common.h"

/*
 * OpenVPN static mutex locks, by mutex type
 */
#define L_MSG       0
#define L_TLS       1
#define L_SOCK      2
#define L_INET_NTOA 3
#define L_CTIME     4
#define L_STRERR    5
#define L_PUTENV    6
#define L_PRNG      7
#define L_GC_MALLOC 8
#define N_MUTEXES   9

#ifdef USE_PTHREAD

typedef pthread_t openvpn_thread_t;

extern bool pthread_initialized;
extern pthread_mutex_t pthread_lock[N_MUTEXES];

#define MUTEX_DEFINE(lock)         pthread_mutex_t lock
#define MUTEX_INIT(lock)           pthread_mutex_init (&lock, NULL)
#define MUTEX_DESTROY(lock)        pthread_mutex_destroy (&lock)
#define MUTEX_LOCK(lock)           pthread_mutex_lock (&lock)
#define MUTEX_UNLOCK(lock)         pthread_mutex_unlock (&lock)

static inline bool
openvpn_thread_enabled (void)
{
  return pthread_initialized;
}

static inline openvpn_thread_t
openvpn_thread_self (void)
{
  return pthread_initialized ? pthread_self() : 0;
}

static inline void
mutex_lock (int type)
{
  if (pthread_initialized)
    pthread_mutex_lock (&pthread_lock[type]);
}

static inline void
mutex_unlock (int type)
{
  if (pthread_initialized)
    {
      pthread_mutex_unlock (&pthread_lock[type]);
#if 1 // JYFIXME
      /* DEBUGGING -- if race conditions exist, make them more likely to occur */
      sleep (0);
#endif
    }
}

static inline void
mutex_cycle (int type)
{
  if (pthread_initialized)
    {
      pthread_mutex_unlock (&pthread_lock[type]);
      sleep (0);
      pthread_mutex_lock (&pthread_lock[type]);
    }
}

void openvpn_thread_init (void);
void openvpn_thread_cleanup (void);

openvpn_thread_t openvpn_thread_create (void *(*start_routine) (void *), void* arg);
void openvpn_thread_join (openvpn_thread_t id);

#else /* USE_PTHREAD */

typedef int openvpn_thread_t;

#define MUTEX_DEFINE(lock)
#define MUTEX_INIT(lock)
#define MUTEX_DESTROY(lock)
#define MUTEX_LOCK(lock)
#define MUTEX_UNLOCK(lock)

static inline bool
openvpn_thread_enabled (void)
{
  return false;
}

static inline openvpn_thread_t
openvpn_thread_self (void)
{
  return 0;
}

static inline void
openvpn_thread_init (void)
{
}

static inline void
openvpn_thread_cleanup (void)
{
}

static inline openvpn_thread_t
openvpn_thread_create (void *(*start_routine) (void *), void* arg)
{
  return 0;
}

static inline void
work_thread_join (openvpn_thread_t id)
{
}

static inline void
mutex_lock (int type)
{
}

static inline void
mutex_unlock (int type)
{
}

static inline void
mutex_cycle (int type)
{
}

#endif /* USE_PTHREAD */

#endif /* THREAD_H */
