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

#if P2MP

#include "list.h"
#include "misc.h"

#include "memdbg.h"

struct hash *
hash_init (int n_buckets,
	   bool auto_grow,
	   uint32_t (*hash_function)(const void *key, uint32_t iv),
	   bool (*compare_function)(const void *key1, const void *key2))
{
  struct hash *h;
  ALLOC_OBJ_CLEAR (h, struct hash);
  h->n_buckets = n_buckets;
  h->auto_grow = auto_grow;
  h->hash_function = hash_function;
  h->compare_function = compare_function;
  h->iv = get_random ();
  ALLOC_ARRAY_CLEAR (h->buckets, struct hash_bucket, n_buckets);
  return h;
}

void
hash_free (struct hash *hash)
{
  int i;
  for (i = 0; i < hash->n_buckets; ++i)
    {
      struct hash_element *he = hash->buckets[i].list;
      while (he)
	{
	  struct hash_element *next = he->next;
	  free (he);
	  he = next;
	}
    }
  free (hash);
}

void *
hash_lookup_fast (struct hash *hash, const void *key, uint32_t hv)
{
  struct hash_bucket *bucket = &hash->buckets[hv % hash->n_buckets];
  struct hash_element *he = bucket->list;
  struct hash_element *prev = NULL;
  while (he)
    {
      if (hv == he->hash_value && (*hash->compare_function)(key, he->key))
	{
	  /* move to head of list */
	  if (prev)
	    {
	      prev->next = he->next;
	      he->next = bucket->list;
	      bucket->list = he;
	    }
	  return he->value;
	}
      prev = he;
      he = he->next;
    }
  return NULL;
}

bool
hash_remove (struct hash *hash, const void *key)
{
  const uint32_t hv = hash_value (hash, key);
  struct hash_bucket *bucket = &hash->buckets[hv % hash->n_buckets];
  struct hash_element *he = bucket->list;
  struct hash_element *prev = NULL;

  while (he)
    {
      if (hv == he->hash_value && (*hash->compare_function)(key, he->key))
	{
	  if (prev)
	    prev->next = he->next;
	  else
	    bucket->list = he->next;
	  free (he);
	  --hash->n_elements;
	  return true;
	}
      prev = he;
      he = he->next;
    }
  return false;
}

bool
hash_add (struct hash *hash, const void *key, void *value)
{
  const uint32_t hv = hash_value (hash, key);
  struct hash_bucket *bucket = &hash->buckets[hv % hash->n_buckets];
  struct hash_element *he;

  if (hash_lookup_fast (hash, key, hv)) /* already exists? */
    return false;

  ALLOC_OBJ (he, struct hash_element);
  he->value = value;
  he->key = key;
  he->hash_value = hv;
  he->next = bucket->list;
  bucket->list = he;
  ++hash->n_elements;

  return true;
}

void
hash_iterator_init (struct hash *hash, struct hash_iterator *hi)
{
  hi->hash = hash;
  hi->bucket_index = -1;
  hi->elem = NULL;
}

void *
hash_iterator_next (struct hash_iterator *hi)
{
  void *ret = NULL;
  if (hi->elem)
    {
      ret = hi->elem->value;
      hi->elem = hi->elem->next;
    }
  else
    {
      while (++hi->bucket_index < hi->hash->n_buckets)
	{
	  hi->elem = hi->hash->buckets[hi->bucket_index].list;
	  if (hi->elem)
	    {
	      ret = hi->elem->value;
	      hi->elem = hi->elem->next;
	      break;
	    }
	}
    }
  return ret;
}

#ifdef LIST_TEST

/*
 * Test the hash code by implementing a simple
 * word frequency algorithm.
 */

struct word
{
  const char *word;
  int n;
};

uint32_t
word_hash_function (const void *key, uint32_t iv)
{
  const char *str = (const char *) key;
  const int len = strlen (str);
  return hash_func ((const uint8_t *)str, len, iv);
}

bool
word_compare_function (const void *key1, const void *key2)
{
  return strcmp ((const char *)key1, (const char *)key2) == 0;
}

void
list_test (void)
{
  struct gc_arena gc = gc_new ();
  struct hash *hash = hash_init (16384, false, word_hash_function, word_compare_function);

  /* parse words from stdin */
  while (true)
    {
      char buf[512];
      char wordbuf[512];
      int wbi;
      int bi;
      char c;

      if (!fgets(buf, sizeof(buf), stdin))
	break;

      bi = wbi = 0;
      do
	{
	  c = buf[bi++];
	  if (isalnum (c) || c == '_')
	    {
	      ASSERT (wbi < (int) sizeof (wordbuf));
	      wordbuf[wbi++] = c;
	    }
	  else
	    {
	      if (wbi)
		{
		  struct word *w;
		  ASSERT (wbi < (int) sizeof (wordbuf));
		  wordbuf[wbi++] = '\0';
		  
		  /* word is parsed from stdin */

		  /* does it already exist in table? */
		  w = (struct word *) hash_lookup (hash, wordbuf);

		  if (w)
		    {
		      /* yes, increment count */
		      ++w->n;
		    }
		  else
		    {
		      /* no, make a new object */
		      ALLOC_OBJ_GC (w, struct word, &gc);
		      w->word = string_alloc (wordbuf, &gc);
		      w->n = 1;
		      ASSERT (hash_add (hash, w->word, w));
		    }
		}
	      wbi = 0;
	    }
	} while (c);
    }

  /* output contents of hash table */
  {
    struct hash_iterator hi;
    struct word *w;
    hash_iterator_init (hash, &hi);

    while ((w = (struct word *) hash_iterator_next (&hi)))
      {
	printf ("%6d '%s'\n", w->n, w->word);
      }
  }

  hash_free (hash);
  gc_free (&gc);
}

#endif

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 32-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 36+6len instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burlteburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^32 is
acceptable.  Do NOT use for cryptographic purposes.

--------------------------------------------------------------------

mix -- mix 3 32-bit values reversibly.
For every delta with one or two bit set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() was built out of 36 single-cycle latency instructions in a 
  structure that could supported 2x parallelism, like so:
      a -= b; 
      a -= c; x = (c>>13);
      b -= c; a ^= x;
      b -= a; x = (a<<8);
      c -= a; b ^= x;
      c -= b; x = (b>>13);
      ...
  Unfortunately, superscalar Pentiums and Sparcs can't take advantage 
  of that parallelism.  They've also turned some of those single-cycle
  latency instructions into multi-cycle latency instructions.  Still,
  this is the fastest good hash I could find.  There were about 2^^68
  to choose from.  I only looked at a billion or so.

James Yonan Notes:

* This function is faster than it looks, and appears to be
  appropriate for our usage in OpenVPN which is primarily
  for hash-table based address lookup (IPv4, IPv6, and Ethernet MAC).
  NOTE: This function is never used for cryptographic purposes, only
  to produce evenly-distributed indexes into hash tables.

* Benchmark results: 11.39 machine cycles per byte on a P2 266Mhz,
                     and 12.1 machine cycles per byte on a
                     2.2 Ghz P4 when hashing a 6 byte string.
--------------------------------------------------------------------
*/

#define mix(a,b,c)               \
{                                \
  a -= b; a -= c; a ^= (c>>13);  \
  b -= c; b -= a; b ^= (a<<8);   \
  c -= a; c -= b; c ^= (b>>13);  \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16);  \
  c -= a; c -= b; c ^= (b>>5);   \
  a -= b; a -= c; a ^= (c>>3);   \
  b -= c; b -= a; b ^= (a<<10);  \
  c -= a; c -= b; c ^= (b>>15);  \
}

uint32_t
hash_func (const uint8_t *k, uint32_t length, uint32_t initval)
{
  uint32_t a, b, c, len;

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;	     /* the golden ratio; an arbitrary value */
  c = initval;		     /* the previous hash value */

   /*---------------------------------------- handle most of the key */
  while (len >= 12)
    {
      a += (k[0] + ((uint32_t) k[1] << 8)
	         + ((uint32_t) k[2] << 16)
	         + ((uint32_t) k[3] << 24));
      b += (k[4] + ((uint32_t) k[5] << 8)
	         + ((uint32_t) k[6] << 16)
	         + ((uint32_t) k[7] << 24));
      c += (k[8] + ((uint32_t) k[9] << 8)
	         + ((uint32_t) k[10] << 16)
	         + ((uint32_t) k[11] << 24));
      mix (a, b, c);
      k += 12;
      len -= 12;
    }

   /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch (len)		    /* all the case statements fall through */
    {
    case 11:
      c += ((uint32_t) k[10] << 24);
    case 10:
      c += ((uint32_t) k[9] << 16);
    case 9:
      c += ((uint32_t) k[8] << 8);
      /* the first byte of c is reserved for the length */
    case 8:
      b += ((uint32_t) k[7] << 24);
    case 7:
      b += ((uint32_t) k[6] << 16);
    case 6:
      b += ((uint32_t) k[5] << 8);
    case 5:
      b += k[4];
    case 4:
      a += ((uint32_t) k[3] << 24);
    case 3:
      a += ((uint32_t) k[2] << 16);
    case 2:
      a += ((uint32_t) k[1] << 8);
    case 1:
      a += k[0];
      /* case 0: nothing left to add */
    }
  mix (a, b, c);
   /*-------------------------------------- report the result */
  return c;
}

#else
static void dummy(void) {}
#endif /* P2MP */
