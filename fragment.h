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

#include "buffer.h"

#define N_FRAG_BUF          40     /* number of packet buffers, should be <= N_FRAG_ID */

#define FRAG_TTL_SEC        10     /* number of seconds time-to-live for a fragment */
#define FRAG_WAKEUP         15     /* fragment code housekeeping is run once every n seconds */

#define TEST_EXP_SEC        300    /* try to increase MTU size after n seconds by sending big test packet */
#define TEST_EXP_TRIG_PCT   80     /* packet must be this % of max size to trigger N_TEST_SEC */
#define TEST_EXP_PCT        10     /* expansion test packet is this % larger than current max */
#define TEST_CON_PCT        50     /* contraction test packet is this % smaller than current max */

struct fragment_master {
  time_t last_wakeup;
  time_t last_mtu_change;
  int mtu;
  int n_rec_big;
  int n_rec_small;
  int n_sent_big;
  int n_sent_small;
  int max_packet_size_received;    /* this value gets bounced back to peer via fragment_net.max_size_recent */
  uint8_t outgoing_id;
  struct buffer outgoing;
};

/*
 * Don't change these values unless you know what you
 * are doing.
 */
#define N_FRAG_ID         256    /* sequence number wraps to 0 at this value */
#define MAX_FRAGS         32     /* maximum number of fragments per packet */
#define MAX_FRAG_PKT_SIZE 65536  /* maximum packet size */

struct fragment {
  int max_frag_size;                 /* Maximum size of each fragment, or 0 if undef */

  /*
   * 32 bit array corresponding to each fragment.  A 1 bit in element n means that
   * the fragment n has been received.  Needs to have at least MAX_FRAGS bits.
   */
  uint32_t map;

  struct buffer buf;                 /* Fragment assembly buffer */
};

/*
 * Fragment header sent over the wire, depending on flags may be 1, 2, 4, or 6 octets
 * in length.
 */
struct fragment_net {
  /*
   * Flags containing fragment info, fragment type, and indicating whether
   * other data follows.
   */
# define FRAG_ID_MASK       0x1F /* Fragments are numbered 0 through 31 */

# define FRAG_TYPE_MASK     0x60 /* mask for below values */
# define FRAG_TYPE_SHIFT    5    /* shift for below values */
# define FRAG_WHOLE         0      /* packet is whole (not a fragment) */
# define FRAG_YES_NOTLAST   1      /* packet is a fragment, but is not the last fragment (seq_id defined) */
# define FRAG_YES_LAST      2      /* packet is the last fragment (seq_id and max_frag_size defined) */
# define FRAG_TEST          3      /* dummy packet for establishing MTU size */

# define FRAG_MSR           0x80   /* Maximum size of recently received packet (max_size_recent defined) */

  uint8_t flags;

  /*
   * Wrapping sequence ID.
   */
  uint8_t seq_id;             /* Needs to accomodate a value up to N_FRAG_ID - 1 */

  /*
   * The max size of a fragment.  If a fragment is not the last fragment in the packet,
   * then the fragment size is guaranteed to be equal to the max fragment size.  Therefore,
   * max_frag_size is only sent over the wire if FRAG_LAST is set.  Otherwise it is assumed
   * to be the actual fragment size received.
   */
  uint16_t max_frag_size;     /* Needs to accomodate a value up to MAX_FRAG_PKT_SIZE - 1 */

  uint16_t max_size_recent;   /* Largest packet size received recently */
};

#endif
