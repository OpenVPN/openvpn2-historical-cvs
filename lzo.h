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

#ifdef USE_LZO

#include <sys/time.h>
#include "lzo1x.h"
#include "buffer.h"
#include "common.h"

/*
 * Use LZO compress routine lzo1x_1_15_compress which is described
 * as faster but needs a bit more memory than the standard routine.
 * Use safe compress (i.e. check for buffer overflows).
 * You may want to use the non-safe version
 * of decompress if speed is essential and if you know
 * that you will always be using a MAC to verify the
 * integrity of incoming packets.
 */
#define LZO_COMPRESS    lzo1x_1_15_compress
#define LZO_WORKSPACE	LZO1X_1_15_MEM_COMPRESS
#define LZO_DECOMPRESS  lzo1x_decompress_safe

#define LZO_EXTRA_BUFFER(len) ((len)/64 + 16 + 3)	/* LZO worst case size expansion. */

/*
 * Don't try to compress any packet smaller than this.
 */
#define COMPRESS_THRESHOLD 100

/*
 * Adaptive compress parameters
 */
#define AC_SAMP_SEC    2      /* number of seconds in sample period */
#define AC_MIN_BYTES   1000   /* sample period must have at least n bytes
				 to be valid for testing */
#define AC_SAVE_PCT    5      /* turn off compress if we didn't save at
				 least this % during sample period */
#define AC_OFF_SEC     60     /* if we turn off compression, don't do sample
				 retest for n seconds */

struct lzo_adaptive_compress {
  bool enabled;
  bool compress_state;
  time_t next;
  int n_total;
  int n_comp;
};

/*
 * Compress and Uncompress routines.
 */

struct lzo_compress_workspace
{
  lzo_voidp wmem;
  int wmem_size;
  struct lzo_adaptive_compress ac;
};

void lzo_adjust_frame_parameters(struct frame *frame);

void lzo_compress_init (struct lzo_compress_workspace *lzowork, bool adaptive);

void lzo_compress_uninit (struct lzo_compress_workspace *lzowork);

void lzo_compress (struct buffer *buf, struct buffer work,
		   struct lzo_compress_workspace *lzowork,
		   const struct frame* frame,
		   const time_t current);

void lzo_decompress (struct buffer *buf, struct buffer work,
		     struct lzo_compress_workspace *lzowork,
		     const struct frame* frame);

#endif /* USE_LZO */
