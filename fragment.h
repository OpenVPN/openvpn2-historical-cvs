/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
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

#ifndef FRAGMENT_H
#define FRAGMENT_H

#ifdef FRAGMENT_ENABLE

#include "common.h"
#include "buffer.h"
#include "interval.h"
#include "mtu.h"
#include "shaper.h"

#define N_FRAG_BUF                   10      /* number of packet buffers, should be <= N_FRAG_ID */
#define FRAG_TTL_SEC                 10      /* number of seconds time-to-live for a fragment */
#define FRAG_WAKEUP_INTERVAL         5       /* wakeup code called once per n seconds */

#if 0
#define FRAG_INITIAL_BANDWIDTH       10000   /* starting point (bytes per sec) for adaptive bandwidth */
#endif

struct fragment {
  bool defined;

  int max_frag_size;               /* maximum size of each fragment */

  /*
   * 32 bit array corresponding to each fragment.  A 1 bit in element n means that
   * the fragment n has been received.  Needs to have at least MAX_FRAGS bits.
   */
# define FRAG_MAP_MASK 0xFFFFFFFF
# define MAX_FRAGS             32  /* maximum number of fragments per packet */
  unsigned int map;

  time_t timestamp;                /* timestamp for time-to-live purposes */

  struct buffer buf;               /* fragment assembly buffer for received datagrams */
};

struct fragment_list {
  int seq_id;
  int index;
  struct fragment fragments[N_FRAG_BUF];
};

struct fragment_master {
  /* buffer to return "fragmentation needed but DF set" messages? */
  struct buffer icmp_buf;

  struct event_timeout wakeup;     /* when should main openvpn event loop wake us up */

  struct shaper shaper;            /* output bandwidth */

  /* this value is bounced back to peer in FRAG_SIZE with FRAG_WHOLE/FRAG_YES_NOTLAST set */
  int n_packets_received;          /* value is zeroed after send to peer */

  /* number of packets we've sent (without confirming receipt) */
  int n_packets_sent;

  /* a version of n_packets_sent kept in temporal sync with n_packets_sent_confirmed */
  int n_packets_sent_sync;

  /* number of packets queued for send but not actually sent yet */
  int n_packets_sent_pending;

  /* number of packets sent, which were received and confirmed by our peer */
  int n_packets_sent_confirmed;

  /* similar to n_packets_sent, but used to keep track of largest packet size
     which was successfully received by peer */
  int max_packet_size_received;
  int max_packet_size_sent;
  int max_packet_size_sent_sync;
  int max_packet_size_sent_pending;
  int max_packet_size_sent_confirmed;

  /* used to determine whether or not a bandwidth increase was successful */
  int bytes_sent;
  int bytes_sent_sync;

  /* tracking parameters used to determine when outgoing mtu or bandwidth should be raised/lowered */ 
  int mtu_trend;
  int bandwidth_trend;

  /* true if the OS has explicitly recommended an MTU value */
  bool received_os_mtu_hint;

  /* determines which confirmation statistic (number of packets or max packet size)
     is sent in the fragment header */
  bool which_stat_to_send;

  /* storage for possible backtrack in MTU and/or bandwidth parameters */
  struct frame known_good_frame;
  int known_good_bandwidth;

  /* a sequence ID describes a set of fragments that make up one datagram */
# define N_SEQ_ID            256   /* sequence number wraps to 0 at this value (should be a power of 2) */
  int outgoing_seq_id;             /* sent as FRAG_SEQ_ID below */

  /* outgoing packet is possibly sent as a series of fragments */

# define MAX_FRAG_PKT_SIZE 65536   /* maximum packet size */
  int outgoing_frag_size;          /* sent to peer via FRAG_SIZE when FRAG_YES_LAST set */

  int outgoing_frag_id;            /* each fragment in a datagram is numbered 0 to MAX_FRAGS-1 */ 

  struct buffer outgoing;          /* outgoing datagram, free if current_frag_id == 0 */
  struct buffer outgoing_return;   /* buffer to return outgoing fragment to code in openvpn.c */

  /* incoming fragments from remote */
  struct fragment_list incoming;
};

/*
 * Fragment header sent over the wire.
 */

typedef uint32_t fragment_header_type;

/* convert a fragment_header_type from host to network order */
#define hton_fragment_header_type(x) htonl(x)

/* convert a fragment_header_type from network to host order */
#define ntoh_fragment_header_type(x) ntohl(x)

/* FRAG_TYPE 2 bits */
#define FRAG_TYPE_MASK        0x00000003
#define FRAG_TYPE_SHIFT       0

#define FRAG_WHOLE            0    /* packet is whole, FRAG_N_PACKETS_RECEIVED echoed back to peer */
#define FRAG_YES_NOTLAST      1    /* packet is a fragment, but is not the last fragment,
				      FRAG_N_PACKETS_RECEIVED set as above */
#define FRAG_YES_LAST         2    /* packet is the last fragment, FRAG_SIZE = size of non-last frags */
#define FRAG_TEST             3    /* control packet for establishing MTU size */

/* FRAG_SEQ_ID 8 bits */
#define FRAG_SEQ_ID_MASK      0x000000ff
#define FRAG_SEQ_ID_SHIFT     2

/* FRAG_ID 5 bits */
#define FRAG_ID_MASK          0x0000001f
#define FRAG_ID_SHIFT         10

/*
 * FRAG_SIZE  14 bits
 *
 * IF FRAG_YES_LAST (FRAG_SIZE):
 *   The max size of a fragment.  If a fragment is not the last fragment in the packet,
 *   then the fragment size is guaranteed to be equal to the max fragment size.  Therefore,
 *   max_frag_size is only sent over the wire if FRAG_LAST is set.  Otherwise it is assumed
 *   to be the actual fragment size received.
 */

/* FRAG_SIZE 14 bits */
#define FRAG_SIZE_MASK        0x00003fff
#define FRAG_SIZE_SHIFT       15
#define FRAG_SIZE_ROUND_SHIFT 2  /* fragment/datagram sizes represented as multiple of 4 */

#define FRAG_SIZE_ROUND_MASK ((1 << FRAG_SIZE_ROUND_SHIFT) - 1)


/*
 * FRAG_EXTRA 16 bits
 *
 * IF FRAG_WHOLE or FRAG_YES_NOTLAST
 *   if FRAG_EXTRA_FLAG_MASK, max packet size received recently, or 0 if no packets received.
 *   if !FRAG_EXTRA_FLAG_MASK, number of packets received recently, or 0 if no packets received.
 *   The remote peer will reset its stored version of both values to 0 after each send.
 */

#define FRAG_EXTRA_FLAG_MASK    0x00008000

/* FRAG_EXTRA 16 bits */
#define FRAG_EXTRA_MASK         0x0000ffff
#define FRAG_EXTRA_SHIFT        16

#define FRAG_EXTRA_IS_MAX       FRAG_EXTRA_FLAG_MASK

/*
 * Public functions
 */

struct fragment_master *fragment_init (struct frame *frame);

void fragment_frame_init (struct fragment_master *f, const struct frame *frame, bool generate_icmp);

void fragment_free (struct fragment_master *f);

void fragment_incoming (struct fragment_master *f, struct buffer *buf,
			const struct frame* frame, const time_t current);

void fragment_outgoing (struct fragment_master *f, struct buffer *buf,
			const struct frame* frame, const time_t current);

bool fragment_ready_to_send (struct fragment_master *f, struct buffer *buf,
			     const struct frame* frame, const time_t current);

bool fragment_icmp (struct fragment_master *f, struct buffer *buf,
		    const struct frame* frame, const time_t current);

void fragment_received_os_mtu_hint (struct fragment_master *f, const struct frame* frame);

/*
 * Private functions.
 */
void fragment_wakeup (struct fragment_master *f, struct frame *frame, time_t current);

/*
 * Inline functions
 */

static inline void
fragment_housekeeping (struct fragment_master *f, struct frame *frame, time_t current, struct timeval *tv)
{
  if (event_timeout_trigger (&f->wakeup, current))
    fragment_wakeup (f, frame, current);
  event_timeout_wakeup (&f->wakeup, current, tv);
}

static inline bool
fragment_outgoing_defined (struct fragment_master *f)
{
  return f->outgoing.len > 0;
}

static inline void
fragment_post_send (struct fragment_master *f, int len)
{
  shaper_wrote_bytes (&f->shaper, len);

  f->bytes_sent += len;
  f->n_packets_sent += f->n_packets_sent_pending;
  f->max_packet_size_sent = max_int (f->max_packet_size_sent, f->max_packet_size_sent_pending);
  f->n_packets_sent_pending = f->max_packet_size_sent_pending = 0;
}

#endif /* FRAGMENT_ENABLE */

#endif
