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

#include "config.h"
#include "syshead.h"
#include "fragment.h"
#include "memdbg.h"

#define FRAG_ERR(s) { msg = s; goto error; }

static void
fragment_list_buf_init (struct fragment_list *list, const struct frame *frame)
{
  int i;
  for (i = 0; i < N_FRAG_BUF; ++i)
    list->fragments[i].buf = alloc_buf (BUF_SIZE (frame));
}

static void
fragment_list_buf_free (struct fragment_list *list)
{
  int i;
  for (i = 0; i < N_FRAG_BUF; ++i)
    free_buf (&list->fragments[i].buf);
}

/*
 * Given a sequence ID number, get a fragment buffer.  Use a sliding window,
 * similar to packet_id code.
 */
static struct fragment *
fragment_list_get_buf (struct fragment_list *list, int seq_id)
{
  int diff;
  if (abs (diff = modulo_subtract (seq_id, list->seq_id, N_SEQ_ID)) >= N_FRAG_BUF)
    {
      int i;
      for (i = 0; i < N_FRAG_BUF; ++i)
	list->fragments[i].defined = false;
      list->index = 0;
      list->seq_id = seq_id;
      diff = 0;
    }
  while (diff > 0)
    {
      list->fragments[list->index = modulo_add (list->index, 1, N_FRAG_BUF)].defined = false;
      list->seq_id = modulo_add (list->seq_id, 1, N_SEQ_ID);
      --diff;
    }
  return &list->fragments[modulo_add (list->index, diff, N_FRAG_BUF)];
}

struct fragment_master *
fragment_init (struct frame *frame)
{
  struct fragment_master *ret;

  ret = (struct fragment_master *) malloc (sizeof (struct fragment_master));
  ASSERT (ret);
  CLEAR (*ret); /* code that initializes other parts of fragment_master assume an initial CLEAR */
  frame->extra_frame += sizeof(fragment_header_type);

  /*
   * Outgoing sequence ID is randomized to reduce the probability of sequence number collisions
   * when openvpn sessions are restarted.  This is not done out of any need for security, as all
   * fragmentation control information resides inside of the encrypted/authenticated envelope.
   */
  ret->outgoing_seq_id = (int)time(NULL) & (N_SEQ_ID - 1);

  return ret;
}

void
fragment_free (struct fragment_master *f)
{
  fragment_list_buf_free (&f->incoming);
  free_buf (&f->outgoing);
  free_buf (&f->outgoing_return);
  free_buf (&f->icmp_buf);
}

void
fragment_frame_init (struct fragment_master *f, const struct frame *frame, bool generate_icmp)
{
  fragment_list_buf_init (&f->incoming, frame);
  f->outgoing = alloc_buf (BUF_SIZE (frame));
  f->outgoing_return = alloc_buf (BUF_SIZE (frame));
  if (generate_icmp)
    f->icmp_buf = alloc_buf (BUF_SIZE (frame));
}

#define FRAG_ERR(s) { msg = s; goto error; }

/*
 * Accept an incoming datagram (which may be a fragment) from remote.
 * If the datagram is whole (i.e not a fragment), pass through.
 * If the datagram is a fragment, join with other fragments received so far.
 * If a fragment fully completes the datagram, return the datagram.
 */
void
fragment_incoming (struct fragment_master *f, struct buffer *buf,
		   const struct frame* frame, const time_t current)
{
  const char *msg = NULL;
  fragment_header_type flags = 0;
  int frag_type = 0;
  int frag_size = 0;

  if (buf->len > 0)
    {
      /* get flags from packet head */
      if (!buf_read (buf, &flags, sizeof (flags)))
	FRAG_ERR ("flags not found in packet");
      flags = ntoh_fragment_header_type (flags);

      /* remember the maximum payload size received */
      if (buf->len > f->max_packet_size_received)
	f->max_packet_size_received = buf->len;

      /* get fragment type from flags */
      frag_type = ((flags & FRAG_TYPE_MASK) >> FRAG_TYPE_SHIFT);

      /* update max_packet_size_sent_confirmed */
      frag_size = ((flags & FRAG_SIZE_MASK) >> (FRAG_SIZE_SHIFT - FRAG_SIZE_ROUND_SHIFT));
      if ((frag_type == FRAG_WHOLE || frag_type == FRAG_YES_NOTLAST)
	  && (f->max_packet_size_sent_confirmed < frag_size))
	f->max_packet_size_sent_confirmed = frag_size;

      /* handle the fragment type */
      if (frag_type == FRAG_WHOLE)
	{
	  if (flags & (FRAG_SEQ_ID_MASK | FRAG_ID_MASK))
	    FRAG_ERR ("spurrious FRAG_WHOLE flags");
	}
      else if (frag_type == FRAG_YES_NOTLAST || frag_type == FRAG_YES_LAST)
	{
	  const int seq_id = ((flags & FRAG_SEQ_ID_MASK) >> FRAG_SEQ_ID_SHIFT);
	  const int n = ((flags & FRAG_ID_MASK) >> FRAG_ID_SHIFT);
	  const int size = ((frag_type == FRAG_YES_LAST) ? frag_size : buf->len);

	  /* get the appropriate fragment buffer based on received seq_id */
	  struct fragment *frag = fragment_list_get_buf (&f->incoming, seq_id);

	  /* make sure that size is an even multiple of 1<<FRAG_SIZE_ROUND_SHIFT */
	  if (size & FRAG_SIZE_ROUND_MASK)
	    FRAG_ERR ("bad fragment size");

	  /* is this the first fragment for our sequence number? */
	  if (!frag->defined || (frag->defined && frag->max_frag_size != size))
	    {
	      frag->defined = true;
	      frag->max_frag_size = size;
	      frag->map = 0;
	      ASSERT (buf_init (&frag->buf, EXTRA_FRAME (frame)));
	    }

	  /* copy the data to fragment buffer */
	  if (!buf_copy_range (&frag->buf, n * size, buf, 0, buf->len))
	    FRAG_ERR ("fragment buffer overflow");

	  /* set elements in bit array to reflect which fragments have been received */
	  frag->map |= (((frag_type == FRAG_YES_LAST) ? FRAG_MAP_MASK : 1) << n);

	  /* update timestamp on partially built datagram */
	  frag->timestamp = current;

	  /* received full datagram? */
	  if ((frag->map & FRAG_MAP_MASK) == FRAG_MAP_MASK)
	    {
	      frag->defined = false;
	      *buf = frag->buf;
	    }
	  else
	    {
	      buf->len = 0;
	    }
	}
      else if (frag_type == FRAG_TEST)
	{
	  /* CODE ME */
	}
      else
	{
	  FRAG_ERR ("unknown fragment type");
	}
    }

  return;

 error:
  if (msg)
    msg (D_FRAG_ERRORS, "Fragmentation input error flags=" fragment_type_format ": %s", flags, msg);
  buf->len = 0;
  return;
}

static inline void
fragment_prepend_flags (struct buffer *buf, int type, int seq_id, int frag_id, int frag_size, int *max_packet_size_sent)
{
  fragment_header_type flags =
    hton_fragment_header_type ((fragment_header_type)
			       ((type & FRAG_TYPE_MASK) << FRAG_TYPE_SHIFT)
			       | ((seq_id & FRAG_SEQ_ID_MASK) << FRAG_SEQ_ID_SHIFT)
			       | ((frag_id & FRAG_ID_MASK) << FRAG_ID_SHIFT)
			       | (((frag_size >> FRAG_SIZE_ROUND_SHIFT) & FRAG_SIZE_MASK) << FRAG_SIZE_SHIFT));
  if (buf->len > *max_packet_size_sent)
    *max_packet_size_sent = buf->len;
  ASSERT (buf_write_prepend (buf, &flags, sizeof (flags)));
}

void
fragment_outgoing (struct fragment_master *f, struct buffer *buf,
		   const struct frame* frame, const time_t current)
{
  const char *msg = NULL;
  if (buf->len > 0)
    {
      ASSERT (!f->outgoing.len);
      if (buf->len > PAYLOAD_SIZE_DYNAMIC(frame)) /* should we fragment? */
	{
	  /*
	   * Send the datagram as a series of 2 or more fragments.
	   */
	  f->outgoing_frag_size = PAYLOAD_SIZE_DYNAMIC(frame) & ~FRAG_SIZE_ROUND_MASK;
	  if (buf->len > f->outgoing_frag_size * MAX_FRAGS)
	    FRAG_ERR ("too many fragments would be required to send datagram");
	  ASSERT (buf_init (&f->outgoing, EXTRA_FRAME (frame)));
	  ASSERT (buf_copy (&f->outgoing, buf));
	  f->outgoing_seq_id = modulo_add (f->outgoing_seq_id, 1, N_SEQ_ID);
	  f->outgoing_frag_id = 0;
	  buf->len = 0;
	  ASSERT (fragment_ready_to_send (f, buf, frame, current));
	}
      else
	{
	  /*
	   * Send the datagram whole.  Also let the peer know the maximum packet size we've received
	   * from them so far, to help them keep their path MTU correct.
	   */
	  fragment_prepend_flags (buf, FRAG_WHOLE, 0, 0, f->max_packet_size_received, &f->max_packet_size_sent);
	  f->max_packet_size_received = 0;
	}
    }
  return;

 error:
  if (msg)
    msg (D_FRAG_ERRORS, "Fragmentation output error: %s", msg);
  buf->len = 0;
  return;
}

bool fragment_ready_to_send (struct fragment_master *f, struct buffer *buf,
			     const struct frame* frame, const time_t current)
{
  if (f->outgoing.len)
    {
      /* get fragment size, and determine if it is the last fragment */
      int size = f->outgoing_frag_size;
      int last = false;
      if (f->outgoing.len <= size)
	{
	  size = f->outgoing.len;
	  last = true;
	}

      /* initialize return buffer */
      *buf = f->outgoing_return;
      ASSERT (buf_init (buf, EXTRA_FRAME (frame)));
      ASSERT (buf_copy_n (buf, &f->outgoing, size));

      /* fragment flags differ based on whether or not we are sending the last fragment */
      if (last)
	{
	  fragment_prepend_flags (buf,
				  FRAG_YES_LAST,
				  f->outgoing_seq_id,
				  f->outgoing_frag_id,
				  f->outgoing_frag_size,
				  &f->max_packet_size_sent);
	  ASSERT (!f->outgoing.len); /* outgoing buffer length should be zero after last fragment sent */
	}
      else
	{
	  fragment_prepend_flags (buf,
				  FRAG_YES_NOTLAST,
				  f->outgoing_seq_id,
				  f->outgoing_frag_id++,
				  f->max_packet_size_received,
				  &f->max_packet_size_sent);
	  f->max_packet_size_received = 0;
	}
      return true;
    }
  else
    return false;
}

bool
fragment_icmp (struct fragment_master *f, struct buffer *buf,
	       const struct frame* frame, const time_t current)
{
  return false;
}

void
fragment_wakeup (struct fragment_master *f, time_t current)
{
}
