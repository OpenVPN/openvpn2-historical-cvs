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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "thread.h"

#include "memdbg.h"

struct buffer
#ifdef DMALLOC
alloc_buf_debug (size_t size, const char *file, int line)
#else
alloc_buf (size_t size)
#endif
{
  struct buffer buf;
  buf.capacity = (int)size;
  buf.offset = 0;
  buf.len = 0;
#ifdef DMALLOC
  buf.data = (uint8_t *) openvpn_dmalloc (file, line, size);
#else
  buf.data = (uint8_t *) malloc (size);
#endif
  CHECK_MALLOC_RETURN (buf.data);
  if (size)
    *buf.data = 0;
  return buf;
}

struct buffer
#ifdef DMALLOC
alloc_buf_gc_debug (size_t size, struct gc_arena *gc, const char *file, int line)
#else
alloc_buf_gc (size_t size, struct gc_arena *gc)
#endif
{
  struct buffer buf;
  buf.capacity = (int)size;
  buf.offset = 0;
  buf.len = 0;
#ifdef DMALLOC
  buf.data = (uint8_t *) gc_malloc_debug (size, false, gc, file, line);
#else
  buf.data = (uint8_t *) gc_malloc (size, false, gc);
#endif
  if (size)
    *buf.data = 0;
  return buf;
}

struct buffer
#ifdef DMALLOC
clone_buf_debug (const struct buffer* buf, const char *file, int line)
#else
clone_buf (const struct buffer* buf)
#endif
{
  struct buffer ret;
  ret.capacity = buf->capacity;
  ret.offset = buf->offset;
  ret.len = buf->len;
#ifdef DMALLOC
  ret.data = (uint8_t *) openvpn_dmalloc (file, line, buf->capacity);
#else
  ret.data = (uint8_t *) malloc (buf->capacity);
#endif
  CHECK_MALLOC_RETURN (ret.data);
  memcpy (BPTR (&ret), BPTR (buf), BLEN (buf));
  return ret;
}

struct buffer
clear_buf ()
{
  struct buffer buf;
  CLEAR (buf);
  return buf;
}

void
free_buf (struct buffer *buf)
{
  if (buf->data)
    free (buf->data);
  CLEAR (*buf);
}

/*
 * Return a buffer for write that is a subset of another buffer
 */
struct buffer
buf_sub (struct buffer *buf, int size, bool prepend)
{
  struct buffer ret;
  uint8_t *data;

  CLEAR (ret);
  data = prepend ? buf_prepend (buf, size) : buf_write_alloc (buf, size);
  if (data)
    {
      ret.capacity = size;
      ret.data = data;
    }
  return ret;
}

/*
 * printf append to a buffer with overflow check
 */
void
buf_printf (struct buffer *buf, const char *format, ...)
{
  va_list arglist;

  uint8_t *ptr = BEND (buf);
  int cap = buf_forward_capacity (buf);

  if (cap > 0)
    {
      va_start (arglist, format);
      vsnprintf ((char *)ptr, cap, format, arglist);
      va_end (arglist);
      *(buf->data + buf->capacity - 1) = 0; /* windows vsnprintf needs this */
      buf->len += (int) strlen ((char *)ptr);
    }
}

/*
 * This is necessary due to certain buggy implementations of snprintf,
 * that don't guarantee null termination for size > 0.
 */

int openvpn_snprintf(char *str, size_t size, const char *format, ...)
{
  va_list arglist;
  int ret = 0;
  if (size > 0)
    {
      va_start (arglist, format);
      ret = vsnprintf (str, size, format, arglist);
      va_end (arglist);
      str[size - 1] = 0;
    }
  return ret;
}

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void
buf_catrunc (struct buffer *buf, const char *str)
{
  if (buf_forward_capacity (buf) <= 1)
    {
      int len = (int) strlen (str) + 1;
      if (len < buf_forward_capacity_total (buf))
	{
	  strncpynt ((char *)(buf->data + buf->capacity - len), str, len);
	}
    }
}

/*
 * convert a multi-line output to one line
 */
void
convert_to_one_line (struct buffer *buf)
{
  uint8_t *cp = BPTR(buf);
  int len = BLEN(buf);
  while (len--)
    {
      if (*cp == '\n')
	*cp = '|';
      ++cp;
    }
}

/* NOTE: requires that string be null terminated */
void
buf_write_string_file (const struct buffer *buf, const char *filename, int fd)
{
  const int len = strlen (BPTR (buf));
  const int size = write (fd, BPTR (buf), len);
  if (size != len)
    msg (M_ERR, "Write error on file '%s'", filename);
}

/*
 * Garbage collection
 */

void *
#ifdef DMALLOC
gc_malloc_debug (size_t size, bool clear, struct gc_arena *a, const char *file, int line)
#else
gc_malloc (size_t size, bool clear, struct gc_arena *a)
#endif
{
  struct gc_entry *e;
  void *ret;

#ifdef DMALLOC
  e = (struct gc_entry *) openvpn_dmalloc (file, line, size + sizeof (struct gc_entry));
#else
  e = (struct gc_entry *) malloc (size + sizeof (struct gc_entry));
#endif
  CHECK_MALLOC_RETURN (e);
  ret = (char *) e + sizeof (struct gc_entry);
  if (clear)
    memset (ret, 0, size);
  mutex_lock_static (L_GC_MALLOC);
  e->next = a->list;
  a->list = e;
  mutex_unlock_static (L_GC_MALLOC);
  return ret;
}

void
x_gc_free (struct gc_arena *a)
{
  struct gc_entry *e;
  mutex_lock_static (L_GC_MALLOC);
  e = a->list;
  a->list = NULL;
  mutex_unlock_static (L_GC_MALLOC);
  
  while (e != NULL)
    {
      struct gc_entry *next = e->next;
      free (e);
      e = next;
    }
}

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */

char *
format_hex_ex (const uint8_t *data, int size, int maxoutput,
	       int space_break, const char* separator,
	       struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (maxoutput ? maxoutput :
				    ((size * 2) + (size / space_break) + 2),
				    gc);
  int i;
  for (i = 0; i < size; ++i)
    {
      if (separator && i && !(i % space_break))
	buf_printf (&out, "%s", separator);
      buf_printf (&out, "%02x", data[i]);
    }
  buf_catrunc (&out, "[more...]");
  return (char *)out.data;
}

/*
 * remove specific trailing character
 */

void
buf_rmtail (struct buffer *buf, uint8_t remove)
{
  uint8_t *cp = BLAST(buf);
  if (cp && *cp == remove)
    {
      *cp = '\0';
      --buf->len;
    }
}

/*
 * Remove trailing \r and \n chars.
 */
void
chomp (char *str)
{
  bool modified;
  do {
    const int len = strlen (str);
    modified = false;
    if (len > 0)
      {
	char *cp = str + (len - 1);
	if (*cp == '\n' || *cp == '\r')
	  {
	    *cp = '\0';
	    modified = true;
	  }
      }
  } while (modified);
}

/*
 * Allocate a string
 */
char *
#ifdef DMALLOC
string_alloc_debug (const char *str, struct gc_arena *gc, const char *file, int line)
#else
string_alloc (const char *str, struct gc_arena *gc)
#endif
{
  if (str)
    {
      const int n = strlen (str) + 1;
      char *ret;

      if (gc)
	{
#ifdef DMALLOC
	  ret = (char *) gc_malloc_debug (n, false, gc, file, line);
#else
	  ret = (char *) gc_malloc (n, false, gc);
#endif
	}
      else
	{
#ifdef DMALLOC
	  ret = (char *) openvpn_dmalloc (file, line, n);
#else
	  ret = (char *) malloc (n);
#endif
	  CHECK_MALLOC_RETURN (ret);
	}
      memcpy (ret, str, n);
      return ret;
    }
  else
    return NULL;
}

/*
 * String comparison
 */

bool
buf_string_match_head_str (const struct buffer *src, const char *match)
{
  const int size = strlen (match);
  if (size < 0 || size > src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

bool
buf_string_compare_advance (struct buffer *src, const char *match)
{
  if (buf_string_match_head_str (src, match))
    {
      buf_advance (src, strlen (match));
      return true;
    }
  else
    return false;
}

/*
 * String parsing
 */

bool
buf_parse (struct buffer *buf, const int delim, char *line, const int size)
{
  bool eol = false;
  int n = 0;
  int c;

  ASSERT (size > 0);

  do
    {
      c = buf_read_u8 (buf);
      if (c < 0)
	eol = true;
      if (c <= 0 || c == delim)
	c = 0;
      if (n >= size)
	break;
      line[n++] = c;
    }
  while (c);

  line[size-1] = '\0';
  return !(eol && !strlen (line));
}
