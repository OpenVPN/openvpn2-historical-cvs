/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002 James Yonan <jim@yonan.net>
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

/*
 * These routines are designed to catch replay attacks,
 * where a man-in-the-middle captures packets and then
 * attempts to replay them back later.
 */

#ifdef USE_CRYPTO

#ifndef PACKET_ID_H
#define PACKET_ID_H

/*
 * Enables OpenVPN to be compiled in special packet_id test mode.
 */
/*#define PID_TEST*/

#include "circ_list.h"
#include "buffer.h"
#include "error.h"

#if 1
/*
 * These are the types that members of
 * a struct packet_id_net are converted
 * to for network transmission.
 */
typedef uint32_t packet_id_type;
typedef uint32_t net_time_t;

/*
 * In TLS mode, when a packet ID gets to this level,
 * start thinking about triggering a new
 * SSL/TLS handshake.
 */
#define PACKET_ID_WRAP_TRIGGER 0xFF000000

/* convert a packet_id_type from host to network order */
#define htonpid(x) htonl(x)

/* convert a packet_id_type from network to host order */
#define ntohpid(x) ntohl(x)

/* convert a time_t in host order to a net_time_t in network order */
#define htontime(x) htonl((net_time_t)x)

/* convert a net_time_t in network order to a time_t in host order */
#define ntohtime(x) ((time_t)ntohl(x))

#else

/*
 * DEBUGGING ONLY.
 * Make packet_id_type and net_time_t small.
 */

typedef uint8_t packet_id_type;
typedef uint16_t net_time_t;

#define PACKET_ID_WRAP_TRIGGER 0x80

#define htonpid(x) (x)
#define ntohpid(x) (x)
#define htontime(x) htons((net_time_t)x)
#define ntohtime(x) ((time_t)ntohs(x))

#endif

/*
 * Printf formats for special types
 */
#define packet_id_format "%u"

/*
 * Maximum allowed backtrack in
 * sequence number due to packets arriving
 * out of order.
 */
#define PACKET_BACKTRACK_MAX   1024

CIRC_LIST (pkt_id, uint8_t, PACKET_BACKTRACK_MAX);

/*
 * This is the data structure we keep on the receiving side,
 * to check that no packet-id (i.e. sequence number + optional timestamp)
 * was received more than once.
 */
struct packet_id_rec
{
  time_t time;             /* time stamp */
  packet_id_type id;       /* sequence number */
  struct pkt_id id_list;   /* packet-id "memory" */
};

/*
 * file to facilitate cross-session persistence
 * of time/id
 */
struct packet_id_persist
{
  const char *filename;
  int fd;
  time_t time;             /* time stamp */
  packet_id_type id;       /* sequence number */
  time_t time_last_written;
  packet_id_type id_last_written;
  time_t last_flush;
};

struct packet_id_persist_file_image
{
  time_t time;             /* time stamp */
  packet_id_type id;       /* sequence number */
};

/*
 * Keep a record of our current packet-id state
 * on the sending side.
 */
struct packet_id_send
{
  packet_id_type id;
  time_t time;
};

/*
 * Communicate packet-id over the wire.
 * A short packet-id is just a 32 bit
 * sequence number.  A long packet-id
 * includes a timestamp as well.
 *
 * Long packet-ids are used as IVs for
 * CFB/OFB ciphers.
 *
 * This data structure is always sent
 * over the net in network byte order,
 * by calling htonpid, ntohpid,
 * htontime, and ntohtime on the
 * data elements to change them
 * to and from standard sizes.
 *
 * In addition, time is converted to
 * a net_time_t before sending,
 * since openvpn always
 * uses a 32-bit time_t but some
 * 64 bit platforms use a
 * 64 bit time_t.
 */
struct packet_id_net
{
  packet_id_type id;
  time_t time; /* converted to net_time_t before transmission */
};

struct packet_id
{
  struct packet_id_send send;
  struct packet_id_rec rec;
};

/* should we accept an incoming packet id ? */
bool packet_id_test (const struct packet_id_rec *p, const struct packet_id_net *pin);

/* change our current state to reflect an accepted packet id */
void packet_id_add (struct packet_id_rec *p, const struct packet_id_net *pin);

/*
 * packet ID persistence
 */

/* initialize the packet_id_persist structure in a disabled state */
void packet_id_persist_init (struct packet_id_persist *p);

/* close the file descriptor if it is open, and switch to disabled state */
void packet_id_persist_close (struct packet_id_persist *p);

/* load persisted rec packet_id (time and id) only once from file, and set state to enabled */
void packet_id_persist_load (struct packet_id_persist *p, const char *filename);

/* save persisted rec packet_id (time and id) to file (only if enabled state) */
void packet_id_persist_save (struct packet_id_persist *p);

/* transfer packet_id_persist -> packet_id */
void packet_id_persist_load_obj (const struct packet_id_persist *p, struct packet_id* pid);

/* return an ascii string representing a packet_id_persist object */
const char *packet_id_persist_print (const struct packet_id_persist *p);

/*
 * Inline functions.
 */

/* are we in enabled state? */
static inline bool
packet_id_persist_enabled (const struct packet_id_persist *p)
{
  return p->fd >= 0;
}

/* transfer packet_id -> packet_id_persist */
static inline void
packet_id_persist_save_obj (struct packet_id_persist *p, const struct packet_id* pid)
{
  if (packet_id_persist_enabled (p) && pid->rec.time)
    {
      p->time = pid->rec.time;
      p->id = pid->rec.id;
    }
}

/* flush the current packet_id to disk, once per n seconds */
static inline void
packet_id_persist_flush (struct packet_id_persist *p, time_t current, int n)
{
  if (packet_id_persist_enabled (p))
    {
      if (!p->last_flush || p->last_flush + n < current)
	{
	  packet_id_persist_save (p);
	  p->last_flush = current;
	}
    }
}

const char* packet_id_net_print(const struct packet_id_net *pin);

#ifdef PID_TEST
void packet_id_interactive_test();
#endif

static inline int
packet_id_size (bool long_form)
{
  return sizeof (packet_id_type) + (long_form ? sizeof (net_time_t) : 0);
} 

static inline bool
packet_id_close_to_wrapping (const struct packet_id_send *p)
{
  return p->id >= PACKET_ID_WRAP_TRIGGER;
}

/*
 * Allocate an outgoing packet id.
 * Sequence number ranges from 1 to 2^32-1.
 * In long_form, a time_t is added as well.
 */
static inline void
packet_id_alloc_outgoing (struct packet_id_send *p, struct packet_id_net *pin, bool long_form)
{
  if (!p->time)
    p->time = time (NULL);
  pin->id = ++p->id;
  if (!pin->id)
    {
      ASSERT (long_form);
      p->time = time (NULL);
      pin->id = p->id = 1;
    }
  pin->time = p->time;
}

/*
 * Read/write a packet ID to/from the buffer.  Short form is sequence number
 * only.  Long form is sequence number and timestamp.
 */

static inline bool
packet_id_read (struct packet_id_net *pin, struct buffer *buf, bool long_form)
{
  packet_id_type net_id;
  net_time_t net_time;

  pin->id = 0;
  pin->time = 0;

  if (!buf_read (buf, &net_id, sizeof (net_id)))
    return false;
  pin->id = ntohpid (net_id);
  if (long_form)
    {
      if (!buf_read (buf, &net_time, sizeof (net_time)))
	return false;
      pin->time = ntohtime (net_time);
    }
  return true;
}

static inline bool
packet_id_write (const struct packet_id_net *pin, struct buffer *buf, bool long_form, bool prepend)
{
  packet_id_type net_id = htonpid (pin->id);
  net_time_t net_time = htontime (pin->time);

  if (prepend)
    {
      if (long_form)
	{
	  if (!buf_write_prepend (buf, &net_time, sizeof (net_time)))
	    return false;
	}
      if (!buf_write_prepend (buf, &net_id, sizeof (net_id)))
	return false;
    }
  else
    {
      if (!buf_write (buf, &net_id, sizeof (net_id)))
	return false;
      if (long_form)
	{
	  if (!buf_write (buf, &net_time, sizeof (net_time)))
	    return false;
	}
    }
  return true;
}

#endif /* PACKET_ID_H */
#endif /* USE_CRYPTO */
