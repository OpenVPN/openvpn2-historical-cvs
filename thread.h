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
#define L_UNUSED       0
#define L_CTIME        1
#define L_INET_NTOA    2
#define L_MSG          3  /* PTHREAD_MUTEX_RECURSIVE */
#define L_STRERR       4
#define L_PUTENV       5
#define L_PRNG         6
#define L_GETTIMEOFDAY 7
#define L_ENV_SET      8
#define L_SYSTEM       9
#define L_CREATE_TEMP  10
#define L_PLUGIN       11
#define L_VOUT         12
#define N_MUTEXES      13

#ifdef USE_PTHREAD

#define MAX_THREADS     50

#define CACHE_LINE_SIZE 128

/*
 * Improve SMP performance by making sure that each
 * mutex resides in its own cache line.
 */
struct sparse_mutex
{
  pthread_mutex_t mutex;
  uint8_t dummy [CACHE_LINE_SIZE - sizeof (pthread_mutex_t)];
};

typedef pthread_t openvpn_thread_t;

extern bool pthread_initialized;

extern struct sparse_mutex mutex_array[N_MUTEXES];

extern openvpn_thread_t primary_thread_id;

#define MUTEX_DEFINE(lock) pthread_mutex_t lock
#define MUTEX_PTR_DEFINE(lock) pthread_mutex_t *lock

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

static inline bool
openvpn_thread_primary (void)
{
  return !pthread_initialized || primary_thread_id == pthread_self();
}

static inline void
mutex_init (pthread_mutex_t *mutex)
{
  if (mutex)
    pthread_mutex_init (mutex, NULL);
}

static inline void
mutex_destroy (pthread_mutex_t *mutex)
{
  if (mutex)
    pthread_mutex_destroy (mutex);
}

static inline void
mutex_lock (pthread_mutex_t *mutex)
{
  if (pthread_initialized && mutex)
    pthread_mutex_lock (mutex);
}

static inline bool
mutex_trylock (pthread_mutex_t *mutex)
{
  if (pthread_initialized && mutex)
    return pthread_mutex_trylock (mutex) == 0;
  else
    return true;
}

static inline void
mutex_unlock (pthread_mutex_t *mutex)
{
  if (pthread_initialized && mutex)
    {
      pthread_mutex_unlock (mutex);
#if 1 /* JYFIXME: if race conditions exist, make them more likely to occur */
      sleep (0);
#endif
    }
}

static inline void
mutex_cycle (pthread_mutex_t *mutex)
{
  if (pthread_initialized && mutex)
    {
      pthread_mutex_unlock (mutex);
      sleep (0);
      pthread_mutex_lock (mutex);
    }
}

static inline void
mutex_lock_static (int type)
{
  mutex_lock (&mutex_array[type].mutex);
}

static inline bool
mutex_trylock_static (int type)
{
  return mutex_trylock (&mutex_array[type].mutex);
}

static inline void
mutex_unlock_static (int type)
{
  mutex_unlock (&mutex_array[type].mutex);
}

static inline void
mutex_cycle_static (int type)
{
  mutex_cycle (&mutex_array[type].mutex);
}

void openvpn_thread_init (void);
void openvpn_thread_cleanup (void);

openvpn_thread_t openvpn_thread_create (void *(*start_routine) (void *), void* arg);
void openvpn_thread_join (openvpn_thread_t id);

#else /* USE_PTHREAD */

typedef int openvpn_thread_t;

#ifdef _MSC_VER

#define MUTEX_DEFINE(lock) int eat_semicolon
#define MUTEX_PTR_DEFINE(lock) int eat_semicolon

#else

#define MUTEX_DEFINE(lock)
#define MUTEX_PTR_DEFINE(lock)

#endif

#define mutex_init(m)
#define mutex_destroy(m)
#define mutex_lock(m)
#define mutex_trylock(m) (true)
#define mutex_unlock(m)
#define mutex_cycle(m)

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
openvpn_thread_join (openvpn_thread_t id)
{
}

static inline void
mutex_lock_static (int type)
{
}

static inline void
mutex_unlock_static (int type)
{
}

static inline void
mutex_cycle_static (int type)
{
}

static inline bool
openvpn_thread_primary (void)
{
  return true;
}

#endif /* USE_PTHREAD */

#endif /* THREAD_H */
