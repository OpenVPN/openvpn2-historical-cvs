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

#ifdef ENABLE_PLUGIN

#include "buffer.h"
#include "error.h"
#include "misc.h"
#include "plugin.h"

#include "memdbg.h"

static const char *
plugin_type_name (const int type)
{
  switch (type)
    {
    case PLUGIN_UP:
      return "PLUGIN_UP";
    case PLUGIN_DOWN:
      return "PLUGIN_DOWN";
    case PLUGIN_ROUTE_UP:
      return "PLUGIN_ROUTE_UP";
    case PLUGIN_IPCHANGE:
      return "PLUGIN_IPCHANGE";
    case PLUGIN_TLS_VERIFY:
      return "PLUGIN_TLS_VERIFY";
    case PLUGIN_AUTH_USER_PASS_VERIFY:
      return "PLUGIN_AUTH_USER_PASS_VERIFY";
    case PLUGIN_CLIENT_CONNECT:
      return "PLUGIN_CLIENT_CONNECT";
    case PLUGIN_CLIENT_DISCONNECT:
      return "PLUGIN_CLIENT_DISCONNECT";
    case PLUGIN_LEARN_ADDRESS:
      return "PLUGIN_LEARN_ADDRESS";
    default:
      return "PLUGIN_???";
    }
}

static const char *
plugin_mask_string (const unsigned int type_mask, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  bool first = true;
  int i;

  for (i = 0; i < PLUGIN_N; ++i)
    {
      if (PLUGIN_MASK (i) & type_mask)
	{
	  if (!first)
	    buf_printf (&out, "|");
	  buf_printf (&out, "%s", plugin_type_name (i));
	  first = false;
	}
    }
  return BSTR (&out);
}

static inline unsigned int
plugin_supported_types (void)
{
  return ((1<<PLUGIN_N)-1);
}

struct plugin_option_list *
plugin_option_list_new (struct gc_arena *gc)
{
  struct plugin_option_list *ret;
  ALLOC_OBJ_CLEAR_GC (ret, struct plugin_option_list, gc);
  return ret;
}

bool
plugin_option_list_add (struct plugin_option_list *list, const char *so_pathname, const char *args)
{
  if (list->n < MAX_PLUGINS)
    {
      struct plugin_option *o = &list->plugins[list->n++];
      o->so_pathname = so_pathname;
      o->args = args;
      return true;
    }
  else
    return false;
}

void
plugin_option_list_print (const struct plugin_option_list *list, int msglevel)
{
  int i;
  for (i = 0; i < list->n; ++i)
    {
      const struct plugin_option *o = &list->plugins[i];
      msg (msglevel, "  plugin[%d] %s '%s'", i, o->so_pathname, o->args);
    }
}

#if defined(USE_LIBDL)

static void
libdl_resolve_symbol (void *handle, void **dest, const char *symbol, const char *plugin_name)
{
  *dest = dlsym (handle, symbol);
  if (!*dest)
    msg (M_FATAL, "PLUGIN: could not find symbol '%s' in plugin shared object %s", symbol, plugin_name);
}

#elif defined(USE_LOAD_LIBRARY)

static void
dll_resolve_symbol (HMODULE module, void **dest, const char *symbol, const char *plugin_name)
{
  *dest = GetProcAddress (module, symbol);
  if (!*dest)
    msg (M_FATAL, "PLUGIN: could not find symbol '%s' in plugin DLL %s", symbol, plugin_name);
}

#endif

static void
plugin_init_item (struct plugin *p, const struct plugin_option *o, const char **envp)
{
  struct gc_arena gc = gc_new ();
  int status;
  const char **argv = make_arg_array (o->so_pathname, o->args, &gc);
  p->so_pathname = o->so_pathname;
  p->plugin_type_mask = plugin_supported_types ();

#if defined(USE_LIBDL)
  p->handle = dlopen (p->so_pathname, RTLD_NOW);
  if (!p->handle)
    msg (M_FATAL, "PLUGIN: could not load plugin shared object: %s", p->so_pathname);
  libdl_resolve_symbol (p->handle, (void*)&p->open,  "plugin_open_v1", p->so_pathname);
  libdl_resolve_symbol (p->handle, (void*)&p->func,  "plugin_func_v1", p->so_pathname);
  libdl_resolve_symbol (p->handle, (void*)&p->close, "plugin_close_v1", p->so_pathname);
#elif defined(USE_LOAD_LIBRARY)
  p->module = LoadLibrary (p->so_pathname);
  if (!p->module)
    msg (M_ERR, "PLUGIN: could not load plugin DLL: %s", p->so_pathname);
  dll_resolve_symbol (p->module, (void*)&p->open,  "plugin_open_v1", p->so_pathname);
  dll_resolve_symbol (p->module, (void*)&p->func,  "plugin_func_v1", p->so_pathname);
  dll_resolve_symbol (p->module, (void*)&p->close, "plugin_close_v1", p->so_pathname);
#endif

  status = (*p->open)(&p->plugin_type_mask, argv, envp);

  msg (D_PLUGIN, "PLUGIN: INIT %s '%s' intercepted=%s status=%d",
       p->so_pathname,
       o->args ? o->args : "[NULL]",
       plugin_mask_string (p->plugin_type_mask, &gc),
       status);

  if (status)
    msg (M_FATAL, "PLUGIN: plugin initialization function failed with status %d: %s",
	 status,
	 p->so_pathname);

  gc_free (&gc);
}

static bool
plugin_call_item (const struct plugin *p, const int type, const char *args, const char **envp)
{
  int status = false;

  if (p->plugin_type_mask & PLUGIN_MASK (type))
    {
      struct gc_arena gc = gc_new ();
      const char **argv = make_arg_array (p->so_pathname, args, &gc);

      status = (*p->func)(type, argv, envp);

      msg (D_PLUGIN, "PLUGIN: %s/%s status=%d",
	   p->so_pathname,
	   plugin_type_name (type),
	   status);

      if (status)
	msg (M_WARN, "PLUGIN: plugin function %s failed with status %d: %s",
	     plugin_type_name (type),
	     status,
	     p->so_pathname);

      gc_free (&gc);
    }
  return status;
}

static void
plugin_close_item (const struct plugin *p)
{
  msg (D_PLUGIN, "PLUGIN: CLOSE %s",
       p->so_pathname);

  (*p->close)();
#if defined(USE_LIBDL)
  if (dlclose (p->handle))
    msg (M_WARN, "PLUGIN: dlclose() failed on plugin: %s", p->so_pathname);
#elif defined(USE_LOAD_LIBRARY)
  if (!FreeLibrary (p->module))
    msg (M_WARN, "PLUGIN: FreeLibrary() failed on plugin: %s", p->so_pathname);
#endif
}

struct plugin_list *
plugin_list_open (const struct plugin_option_list *list, const struct env_set *es)
{
  struct gc_arena gc = gc_new ();
  int i;
  struct plugin_list *pl;
  const char **envp;

  ALLOC_OBJ_CLEAR (pl, struct plugin_list);

  envp = make_env_array (es, &gc);

  for (i = 0; i < list->n; ++i)
    plugin_init_item (&pl->plugins[i], &list->plugins[i], envp);

  pl->n = list->n;

  gc_free (&gc);
  return pl;
}

int
plugin_call (const struct plugin_list *pl, const int type, const char *args, struct env_set *es)
{
  int ret = false;

  if (plugin_defined (pl, type))
    {
      struct gc_arena gc = gc_new ();
      int i;
      const char **envp;
      
      mutex_lock_static (L_PLUGIN);

      setenv_del (es, "script_type");
      envp = make_env_array (es, &gc);

      for (i = 0; i < pl->n; ++i)
	{
	  if (plugin_call_item (&pl->plugins[i], type, args, envp)) /* if any one plugin in the chain fails, return failure */
	    {
	      ret = true;
	      break;
	    }
	}

      mutex_unlock_static (L_PLUGIN);

      gc_free (&gc);
    }

  return ret;
}

void
plugin_list_close (struct plugin_list *pl)
{
  if (pl)
    {
      int i;

      for (i = 0; i < pl->n; ++i)
	plugin_close_item (&pl->plugins[i]);
      free (pl);
    }
}

bool
plugin_defined (const struct plugin_list *pl, const int type)
{
  int ret = false;
  if (pl)
    {
      int i;
      const unsigned int mask = PLUGIN_MASK (type);
      for (i = 0; i < pl->n; ++i)
	{
	  if (pl->plugins[i].plugin_type_mask & mask)
	    {
	      ret = true;
	      break;
	    }
	}
    }
  return ret;
}

#else
static void dummy(void) {}
#endif /* ENABLE_PLUGIN */
