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

#ifndef BUFFER_H
#define BUFFER_H

#include "basic.h"
#include "thread.h"

/* basic buffer class for OpenVPN */

struct buffer
{
  int capacity;	   /* size of buffer allocated by malloc */
  int offset;	   /* data starts at data + offset, offset > 0 to allow for efficient prepending */
  int len;	   /* length of data that starts at data + offset */
  uint8_t *data;
};

/* for garbage collection */

struct gc_entry
{
  struct gc_entry *next;
};

struct gc_arena
{
  struct gc_entry *list;
};

#define BPTR(buf)  ((buf)->data + (buf)->offset)
#define BEND(buf)  (BPTR(buf) + (buf)->len)
#define BLAST(buf) (((buf)->data && (buf)->len) ? (BPTR(buf) + (buf)->len - 1) : NULL)
#define BLEN(buf)  ((buf)->len)
#define BDEF(buf)  ((buf)->data != NULL)
#define BSTR(buf)  ((char *)BPTR(buf))
#define BCAP(buf)  (buf_forward_capacity (buf))

void buf_clear (struct buffer *buf);

struct buffer clear_buf (void);
void free_buf (struct buffer *buf);

/* for dmalloc debugging */

#ifdef DMALLOC

#define alloc_buf(size)               alloc_buf_debug (size, __FILE__, __LINE__)
#define alloc_buf_gc(size, gc)        alloc_buf_gc_debug (size, gc, __FILE__, __LINE__);
#define clone_buf(buf)                clone_buf_debug (buf, __FILE__, __LINE__);
#define gc_malloc(size, clear, arena) gc_malloc_debug (size, clear, arena, __FILE__, __LINE__)
#define string_alloc(str, gc)         string_alloc_debug (str, gc, __FILE__, __LINE__)

struct buffer alloc_buf_debug (size_t size, const char *file, int line);
struct buffer alloc_buf_gc_debug (size_t size, struct gc_arena *gc, const char *file, int line);
struct buffer clone_buf_debug (const struct buffer* buf, const char *file, int line);
void *gc_malloc_debug (size_t size, bool clear, struct gc_arena *a, const char *file, int line);
char *string_alloc_debug (const char *str, struct gc_arena *gc, const char *file, int line);

#else

struct buffer alloc_buf (size_t size);
struct buffer alloc_buf_gc (size_t size, struct gc_arena *gc); /* allocate buffer with garbage collection */
struct buffer clone_buf (const struct buffer* buf);
void *gc_malloc (size_t size, bool clear, struct gc_arena *a);
char *string_alloc (const char *str, struct gc_arena *gc);

#endif

/* inline functions */

static inline void
buf_reset (struct buffer *buf)
{
  buf->capacity = 0;
  buf->offset = 0;
  buf->len = 0;
  buf->data = NULL;
}

static inline bool
buf_init (struct buffer *buf, int offset)
{
  if (offset < 0 || offset > buf->capacity || buf->data == NULL)
    return false;
  buf->len = 0;
  buf->offset = offset;
  return true;
}

static inline bool
buf_defined (struct buffer *buf)
{
  return buf->data != NULL;
}

static inline void
buf_set_write (struct buffer *buf, uint8_t *data, int size)
{
  buf->len = 0;
  buf->offset = 0;
  buf->capacity = size;
  buf->data = data;
  if (size > 0 && data)
    *data = 0;
}

static inline void
buf_set_read (struct buffer *buf, uint8_t *data, int size)
{
  buf->len = buf->capacity = size;
  buf->offset = 0;
  buf->data = data;
}

/* Like strncpy but makes sure dest is always null terminated */
static inline void
strncpynt (char *dest, const char *src, size_t maxlen)
{
  strncpy (dest, src, maxlen);
  if (maxlen > 0)
    dest[maxlen - 1] = 0;
}

/* return true if string contains at least one numerical digit */
static inline bool
has_digit (const char* src)
{
  char c;
  while ((c = *src++))
    {
      if (isdigit(c))
	return true;
    }
  return false;
}

/*
 * printf append to a buffer with overflow check
 */
void buf_printf (struct buffer *buf, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

/*
 * Like snprintf but guarantees null termination for size > 0
 */
int openvpn_snprintf(char *str, size_t size, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 3, 4)))
#endif
    ;

/*
 * remove trailing characters
 */

void buf_rmtail (struct buffer *buf, uint8_t remove);
void chomp (char *str);

/*
 * Write string in buf to file descriptor fd.
 * NOTE: requires that string be null terminated.
 */
void buf_write_string_file (const struct buffer *buf, const char *filename, int fd);

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void buf_catrunc (struct buffer *buf, const char *str);

/*
 * convert a multi-line output to one line
 */
void convert_to_one_line (struct buffer *buf);

/*
 * Parse a string based on a given delimiter char
 */
bool buf_parse (struct buffer *buf, const int delim, char *line, const int size);

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */
char *
format_hex_ex (const uint8_t *data, int size, int maxoutput,
	       int space_break, const char* separator,
	       struct gc_arena *gc);

static inline char *
format_hex (const uint8_t *data, int size, int maxoutput, struct gc_arena *gc)
{
  return format_hex_ex (data, size, maxoutput, 4, " ", gc);
}

/*
 * Return a buffer that is a subset of another buffer.
 */
struct buffer buf_sub (struct buffer *buf, int size, bool prepend);

/*
 * Check if sufficient space to append to buffer.
 */

static inline bool
buf_safe (struct buffer *buf, int len)
{
  return len >= 0 && buf->offset + buf->len + len <= buf->capacity;
}

static inline int
buf_forward_capacity (struct buffer *buf)
{
  int ret = buf->capacity - (buf->offset + buf->len);
  if (ret < 0)
    ret = 0;
  return ret;
}

static inline int
buf_forward_capacity_total (struct buffer *buf)
{
  int ret = buf->capacity - buf->offset;
  if (ret < 0)
    ret = 0;
  return ret;
}

static inline int
buf_reverse_capacity (struct buffer *buf)
{
  return buf->offset;
}

/*
 * Make space to prepend to a buffer.
 * Return NULL if no space.
 */

static inline uint8_t *
buf_prepend (struct buffer *buf, int size)
{
  if (size < 0 || size > buf->offset)
    return NULL;
  buf->offset -= size;
  buf->len += size;
  return BPTR (buf);
}

static inline bool
buf_advance (struct buffer *buf, int size)
{
  if (size < 0 || buf->len < size)
    return false;
  buf->offset += size;
  buf->len -= size;
  return true;
}

/*
 * Return a pointer to allocated space inside a buffer.
 * Return NULL if no space.
 */

static inline uint8_t *
buf_write_alloc (struct buffer *buf, int size)
{
  uint8_t *ret;
  if (!buf_safe (buf, size))
    return NULL;
  ret = BPTR (buf) + buf->len;
  buf->len += size;
  return ret;
}

static inline uint8_t *
buf_write_alloc_prepend (struct buffer *buf, int size, bool prepend)
{
  return prepend ? buf_prepend (buf, size) : buf_write_alloc (buf, size);
}

static inline uint8_t *
buf_read_alloc (struct buffer *buf, int size)
{
  uint8_t *ret;
  if (size < 0 || buf->len < size)
    return NULL;
  ret = BPTR (buf);
  buf->offset += size;
  buf->len -= size;
  return ret;
}

static inline bool
buf_write (struct buffer *dest, const void *src, int size)
{
  uint8_t *cp = buf_write_alloc (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_write_prepend (struct buffer *dest, const void *src, int size)
{
  uint8_t *cp = buf_prepend (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_write_u8 (struct buffer *dest, int data)
{
  uint8_t u8 = (uint8_t) data;
  return buf_write (dest, &u8, sizeof (uint8_t));
}

static inline bool
buf_write_u16 (struct buffer *dest, int data)
{
  uint16_t u16 = htons ((uint16_t) data);
  return buf_write (dest, &u16, sizeof (uint16_t));
}

static inline bool
buf_write_u32 (struct buffer *dest, int data)
{
  uint32_t u32 = htonl ((uint32_t) data);
  return buf_write (dest, &u32, sizeof (uint32_t));
}

static inline bool
buf_copy (struct buffer *dest, const struct buffer *src)
{
  return buf_write (dest, BPTR (src), BLEN (src));
}

static inline bool
buf_copy_n (struct buffer *dest, struct buffer *src, int n)
{
  uint8_t *cp = buf_read_alloc (src, n);
  if (!cp)
    return false;
  return buf_write (dest, cp, n);
}

static inline bool
buf_copy_range (struct buffer *dest,
		int dest_index,
		const struct buffer *src,
		int src_index,
		int src_len)
{
  if (src_index < 0
      || src_len < 0
      || src_index + src_len > src->len
      || dest_index < 0
      || dest->offset + dest_index + src_len > dest->capacity)
    return false;
  memcpy (dest->data + dest->offset + dest_index, src->data + src->offset + src_index, src_len);
  if (dest_index + src_len > dest->len)
    dest->len = dest_index + src_len;
  return true;
}

/* truncate src to len, copy excess data beyond len to dest */
static inline bool
buf_copy_excess (struct buffer *dest,
		 struct buffer *src,
		 int len)
{
  if (len < 0)
    return false;
  if (src->len > len)
    {
      struct buffer b = *src;
      src->len = len;
      if (!buf_advance (&b, len))
	return false;
      return buf_copy (dest, &b);
    }
  else
    {
      return true;
    }
}

static inline bool
buf_read (struct buffer *src, void *dest, int size)
{
  uint8_t *cp = buf_read_alloc (src, size);
  if (!cp)
    return false;
  memcpy (dest, cp, size);
  return true;
}

static inline int
buf_read_u8 (struct buffer *buf)
{
  int ret;
  if (BLEN (buf) < 1)
    return -1;
  ret = *BPTR(buf);
  buf_advance (buf, 1);
  return ret;
}

static inline int
buf_read_u16 (struct buffer *buf)
{
  uint16_t ret;
  if (!buf_read (buf, &ret, sizeof (uint16_t)))
    return -1;
  return ntohs (ret);
}

static inline uint32_t
buf_read_u32 (struct buffer *buf, bool *good)
{
  uint32_t ret;
  if (!buf_read (buf, &ret, sizeof (uint32_t)))
    {
      if (good)
	*good = false;
      return 0;
    }
  else
    {
      if (good)
	*good = true;
      return ntohl (ret);
    }
}

static inline bool
buf_string_match (const struct buffer *src, const void *match, int size)
{
  if (size != src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

static inline bool
buf_string_match_head (const struct buffer *src, const void *match, int size)
{
  if (size < 0 || size > src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

bool buf_string_match_head_str (const struct buffer *src, const char *match);
bool buf_string_compare_advance (struct buffer *src, const char *match);

/*
 * Bitwise operations
 */
static inline void
xor (uint8_t *dest, const uint8_t *src, int len)
{
  while (len-- > 0)
    *dest++ ^= *src++;
}

/*
 * Very basic garbage collection, mostly for routines that return
 * char ptrs to malloced strings.
 */

void x_gc_free (struct gc_arena *a);

static inline void
gc_init (struct gc_arena *a)
{
  a->list = NULL;
}

static inline void
gc_detach (struct gc_arena *a)
{
  gc_init (a);
}

static inline struct gc_arena
gc_new (void)
{
  struct gc_arena ret;
  ret.list = NULL;
  return ret;
}

static inline void
gc_free (struct gc_arena *a)
{
  if (a->list)
    x_gc_free (a);
}

static inline void
gc_reset (struct gc_arena *a)
{
  gc_free (a);
}

/*
 * Allocate memory to hold a structure
 */

void out_of_memory (void);

#define CHECK_MALLOC_RETURN(p) \
{ \
  if ((p) == NULL) out_of_memory (); \
}

#define ALLOC_OBJ(dptr, type) \
{ \
  CHECK_MALLOC_RETURN ((dptr) = (type *) malloc (sizeof (type))); \
}

#define ALLOC_OBJ_CLEAR(dptr, type) \
{ \
  ALLOC_OBJ (dptr, type); \
  memset ((dptr), 0, sizeof(type)); \
}

#define ALLOC_ARRAY(dptr, type, n) \
{ \
  CHECK_MALLOC_RETURN ((dptr) = (type *) malloc (sizeof (type) * (n))); \
}

#define ALLOC_ARRAY_CLEAR(dptr, type, n) \
{ \
  ALLOC_ARRAY (dptr, type, n); \
  memset ((dptr), 0, (sizeof(type) * (n))); \
}

#define ALLOC_OBJ_GC(dptr, type, gc) \
{ \
  (dptr) = (type *) gc_malloc (sizeof (type), false, (gc)); \
}

#define ALLOC_OBJ_CLEAR_GC(dptr, type, gc) \
{ \
  (dptr) = (type *) gc_malloc (sizeof (type), true, (gc)); \
}

#endif /* BUFFER_H */
