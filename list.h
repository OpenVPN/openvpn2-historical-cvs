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

#ifndef LIST_H
#define LIST_H

/*
 * This code is a fairly straightforward hash
 * table implementation using Bob Jenkins'
 * hash function.
 *
 * Hash tables are used in OpenVPN to keep track of
 * client instances over various key spaces.
 */

#if P2MP

/* define this to enable special list test mode */
/*#define LIST_TEST*/

#include "basic.h"
#include "thread.h"

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

struct hash_element
{
  void *value;
  const void *key;
  unsigned int hash_value;
  struct hash_element *next;
};

struct hash_bucket
{
  MUTEX_DEFINE (mutex);
  struct hash_element * volatile list;
};

struct hash
{
  int n_buckets;
  int mask;
  bool auto_grow; /* not implemented yet */
  uint32_t iv;
  uint32_t (*hash_function)(const void *key, uint32_t iv);
  bool (*compare_function)(const void *key1, const void *key2); /* return true if equal */
  struct hash_bucket *buckets;
};

struct hash_iterator
{
  struct hash *hash;
  int bucket_index;
  struct hash_bucket *bucket;
  struct hash_element *elem;
};

struct hash *hash_init (const int n_buckets,
			const bool auto_grow,
			uint32_t (*hash_function)(const void *key, uint32_t iv),
			bool (*compare_function)(const void *key1, const void *key2));

void hash_free (struct hash *hash);

struct hash_element *hash_lookup_dowork (struct hash *hash,
					 struct hash_bucket *bucket,
					 const void *key,
					 uint32_t hv);

bool hash_remove (struct hash *hash, const void *key);
void hash_remove_by_value (struct hash *hash, void *value);
bool hash_add (struct hash *hash, const void *key, void *value, bool replace);

void hash_iterator_init (struct hash *hash, struct hash_iterator *iter);
struct hash_element *hash_iterator_next (struct hash_iterator *hi);
void hash_iterator_free (struct hash_iterator *hi);

uint32_t hash_func (const uint8_t *k, uint32_t length, uint32_t initval);

#ifdef LIST_TEST
void list_test (void);
#endif

static inline uint32_t
hash_value (const struct hash *hash, const void *key)
{
  return (*hash->hash_function)(key, hash->iv);
}

static inline void *
hash_lookup_lock (struct hash *hash, const void *key, uint32_t hv)
{
  void *ret = NULL;
  struct hash_element *he;
  struct hash_bucket *bucket = &hash->buckets[hv & hash->mask];

  mutex_lock (&bucket->mutex);
  he = hash_lookup_dowork (hash, bucket, key, hv);
  if (he)
    ret = he->value;
  mutex_unlock (&bucket->mutex);

  return ret;
}

static inline void *
hash_lookup (struct hash *hash, const void *key)
{
  return hash_lookup_lock (hash, key, hash_value (hash, key));
}

#endif /* P2MP */
#endif /* LIST */
