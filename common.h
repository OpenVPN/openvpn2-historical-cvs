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

#ifndef COMMON_H
#define COMMON_H

/*
 * Statistics counters.
 */
typedef unsigned long counter_type;

/*
 * Time intervals
 */
typedef int interval_t;

/*
 * Printf formats for special types
 */
#define counter_format          "%10lu"
#define ptr_format              "0x%08zx"
#define time_format             "%lu"
#define fragment_header_format  "0x%08x"

/* these are used to cast the arguments
 * and MUST match the formats above */
typedef unsigned long time_type;

/*
 * Functions used for circular buffer index arithmetic.
 */

/*
 * Return x - y on a circle of circumference mod by shortest path.
 *
 * 0 <= x < mod
 * 0 <= y < mod
 */
static inline int
modulo_subtract(int x, int y, int mod)
{
  const int d1 = x - y;
  const int d2 = (x > y ? -mod : mod) + d1;
  return abs(d1) > abs(d2) ? d2 : d1;
}

/*
 * Return x + y on a circle of circumference mod.
 *
 * 0 <= x < mod
 * -mod <= y <= mod
 */
static inline int
modulo_add(int x, int y, int mod)
{
  int sum = x + y;
  if (sum >= mod)
    sum -= mod;
  if (sum < 0)
    sum += mod;
  return sum;
}

static inline int
max_int (int x, int y)
{
  if (x > y)
    return x;
  else
    return y;
}

static inline int
min_int (int x, int y)
{
  if (x < y)
    return x;
  else
    return y;
}

static inline int
constrain_int (int x, int min, int max)
{
  if (min > max)
    return min;
  if (x < min)
    return min;
  else if (x > max)
    return max;
  else
    return x;
}

#endif
