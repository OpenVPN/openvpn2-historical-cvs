/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
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

#ifndef CIRC_LIST_H
#define CIRC_LIST_H

#include "basic.h"

#define CIRC_LIST(name, type, size) \
struct name { \
  int x_head; \
  int x_size; \
  type x_list[size]; \
}

#define CIRC_LIST_PUSH(obj, item) \
do { \
  if (--obj.x_head < 0) \
    obj.x_head = SIZE(obj.x_list) - 1; \
  if (++obj.x_size >= (int)SIZE(obj.x_list)) \
    obj.x_size = SIZE(obj.x_list); \
  obj.x_list[obj.x_head] = (item); \
} while (0)

#define CIRC_LIST_SIZE(obj) \
  (obj.x_size)

#define CIRC_LIST_INDEX(obj, index) \
  ((obj.x_head + (index)) % SIZE(obj.x_list))

#define CIRC_LIST_ITEM(obj, index) \
  (obj.x_list[CIRC_LIST_INDEX(obj, index)])

#define CIRC_LIST_RESET(obj) \
  CLEAR(obj)

#endif
