/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

/*
 * Support routines for adding/deleting network routes.
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "common.h"
#include "buffer.h"
#include "error.h"
#include "route.h"
#include "misc.h"
#include "socket.h"
#include "tun.h"

#include "memdbg.h"

static void add_route (struct route *r);
static void delete_route (const struct route *r);

static const char *
route_string (const struct route *r)
{
  struct buffer out = alloc_buf_gc (256);
  buf_printf (&out, "ROUTE network %s netmask %s gateway %s",
	      print_in_addr_t (r->network, false),
	      print_in_addr_t (r->netmask, false),
	      print_in_addr_t (r->gateway, false)
	      );
  if (r->metric_defined)
    buf_printf (&out, " metric %d", r->metric);
  return BSTR (&out);
}

static bool
is_route_parm_defined (const char *parm)
{
  if (!parm)
    return false;
  if (!strcmp (parm, "default"))
    return false;
  return true;
}

static void
setenv_route_addr (const char *key, const in_addr_t addr, int i)
{
  char name[128];
  if (i >= 0)
    openvpn_snprintf (name, sizeof (name), "route_%s_%d", key, i);
  else
    openvpn_snprintf (name, sizeof (name), "route_default_%s", key);
  setenv_str (name, print_in_addr_t (addr, false));
}

static bool
init_route (struct route *r,
	    const struct route_option *ro,
	    in_addr_t default_gateway,
	    bool default_gateway_defined)
{
  const in_addr_t default_netmask = ~0;
  bool status;

  r->option = ro;
  r->defined = false;

  /* network */

  if (!is_route_parm_defined (ro->network))
    {
      goto fail;
    }
  r->network = getaddr (
			GETADDR_RESOLVE
			| GETADDR_HOST_ORDER
			| GETADDR_FATAL_ON_SIGNAL,
			ro->network,
			0,
			&status,
			NULL);
  if (!status)
    goto fail;

  /* netmask */

  if (is_route_parm_defined (ro->netmask))
    {
      r->netmask = getaddr (
			    GETADDR_HOST_ORDER
			    | GETADDR_FATAL_ON_SIGNAL,
			    ro->netmask,
			    0,
			    &status,
			    NULL);
      if (!status)
	goto fail;
    }
  else
    r->netmask = default_netmask;

  /* gateway */

  if (is_route_parm_defined (ro->gateway))
    {
      r->gateway = getaddr (
			    GETADDR_RESOLVE
			    | GETADDR_HOST_ORDER
			    | GETADDR_FATAL_ON_SIGNAL,
			    ro->gateway,
			    0,
			    &status,
			    NULL);
      if (!status)
	goto fail;
    }
  else
    {
      if (default_gateway_defined)
	r->gateway = default_gateway;
      else
	{
	  msg (M_WARN, "OpenVPN ROUTE: OpenVPN needs a gateway parameter for a --route option and no default was specified by either --route-gateway --ifconfig options");
	  goto fail;
	}
    }

  /* metric */

  r->metric_defined = false;
  r->metric = 0;
  if (is_route_parm_defined (ro->metric))
    {
      r->metric = atoi (ro->metric);
      if (r->metric < 0)
	{
	  msg (M_WARN, "OpenVPN ROUTE: route metric for network %s (%s) must be >= 0",
	       ro->network,
	       ro->metric);
	  goto fail;
	}
      r->metric_defined = true;
    }
  else
    {
      r->metric = 0;
      r->metric_defined = false;
    }

  r->defined = true;

  return true;

 fail:
  msg (M_WARN, "OpenVPN ROUTE: failed to parse/resolve route for host/network: %s",
       ro->network);
  r->defined = false;
  return false;
}

void
add_route_to_option_list (struct route_option_list *l,
			  const char *network,
			  const char *netmask,
			  const char *gateway,
			  const char *metric)
{
  struct route_option *ro;
  if (l->n >= MAX_ROUTES)
    msg (M_FATAL, "OpenVPN ROUTE: cannot add more than %d routes",
	 MAX_ROUTES);
  ro = &l->routes[l->n];
  ro->network = network;
  ro->netmask = netmask;
  ro->gateway = gateway;
  ro->metric = metric;
  ++l->n;
}

void
clear_route_list (struct route_list *rl)
{
  CLEAR (*rl);
}

bool
init_route_list (struct route_list *rl,
		 const struct route_option_list *opt,
		 const char *default_gateway)
{
  int i;
  bool ret = true;

  clear_route_list (rl);

  if (is_route_parm_defined (default_gateway))
    {
      rl->default_gateway = getaddr (
				     GETADDR_RESOLVE
				     | GETADDR_HOST_ORDER
				     | GETADDR_FATAL_ON_SIGNAL,
				     default_gateway,
				     0,
				     &rl->default_gateway_defined,
				     NULL);

      if (rl->default_gateway_defined)
	{
	  setenv_route_addr ("gateway", rl->default_gateway, -1);
	}
      else
	{
	  msg (M_WARN, "OpenVPN ROUTE: failed to parse/resolve default gateway: %s",
	       default_gateway);
	  ret = false;
	}
    }
  else
    rl->default_gateway_defined = false;

  ASSERT (opt->n >= 0 && opt->n < MAX_ROUTES);

  for (i = 0; i < opt->n; ++i)
    {
      if (!init_route (&rl->routes[i],
		       &opt->routes[i],
		       rl->default_gateway,
		       rl->default_gateway_defined))
	ret = false;
    }

  rl->n = i;
  return ret;
}

void
add_routes (struct route_list *rl, bool delete_first)
{  
  if (!rl->routes_added)
    {
      int i;
      for (i = 0; i < rl->n; ++i)
	{
	  if (delete_first)
	    delete_route (&rl->routes[i]);
	  add_route (&rl->routes[i]);
	}
      rl->routes_added = true;
    }
}

void
delete_routes (struct route_list *rl)
{
  if (rl->routes_added)
    {
      int i;
      for (i = rl->n - 1; i >= 0; --i)
	{
	  const struct route *r = &rl->routes[i];
	  delete_route (r);
	}
      rl->routes_added = false;
    }
}

static const char *
show_opt (const char *option)
{
  if (!option)
    return "nil";
  else
    return option;
}

static void
print_route_option (const struct route_option *ro, int level)
{
  msg (level, "  route %s/%s/%s/%s",
       show_opt (ro->network),
       show_opt (ro->netmask),
       show_opt (ro->gateway),
       show_opt (ro->metric));
}

void
print_route_options (const struct route_option_list *rol,
		     int level)
{
  int i;
  for (i = 0; i < rol->n; ++i)
    print_route_option (&rol->routes[i], level);
}

static void
print_route (const struct route *r, int level)
{
  if (r->defined)
    msg (level, "%s", route_string (r));
}

void
print_routes (const struct route_list *rl, int level)
{
  int i;
  for (i = 0; i < rl->n; ++i)
    print_route (&rl->routes[i], level);
}

static void
setenv_route (const struct route *r, int i)
{
  if (r->defined)
    {
      setenv_route_addr ("network", r->network, i);
      setenv_route_addr ("netmask", r->netmask, i);
      setenv_route_addr ("gateway", r->gateway, i);

      if (r->metric_defined)
	{
	  char name[128];
	  openvpn_snprintf (name, sizeof (name), "route_metric_%d", i);
	  setenv_int (name, r->metric);
	}
    }
}

void
setenv_routes (const struct route_list *rl)
{
  int i;
  for (i = 0; i < rl->n; ++i)
    setenv_route (&rl->routes[i], i + 1);
}

static void
add_route (struct route *r)
{
  int gc_level;
  struct buffer buf;
  const char *network;
  const char *netmask;
  const char *gateway;
  bool status = false;

  if (!r->defined)
    return;

  gc_level = gc_new_level ();
  buf = alloc_buf_gc (256);
  network = print_in_addr_t (r->network, false);
  netmask = print_in_addr_t (r->netmask, false);
  gateway = print_in_addr_t (r->gateway, false);

#if defined(TARGET_LINUX)

  buf_printf (&buf, ROUTE_PATH " add -net %s netmask %s gw %s",
	      network,
	      netmask,
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " metric %d", r->metric);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: Linux route add command failed", false);

#elif defined (WIN32)

  buf_printf (&buf, ROUTE_PATH " ADD %s MASK %s %s",
	      network,
	      netmask,
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " METRIC %d", r->metric);

  netcmd_semaphore_lock ();
  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: Windows route add command failed", false);
  netcmd_semaphore_release ();

#elif defined (TARGET_SOLARIS)

  /* example: route add 192.0.2.32 -netmask 255.255.255.224 somegateway */

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " %s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: Solaris route add command failed", false);

#elif defined(TARGET_FREEBSD)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: FreeBSD route add command failed", false);

#elif defined(TARGET_OPENBSD)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: OpenBSD route add command failed", false);

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

  r->defined = status;
  gc_free_level (gc_level);
}

static void
delete_route (const struct route *r)
{
  int gc_level;
  struct buffer buf;
  const char *network;
  const char *netmask;
  const char *gateway;

  if (!r->defined)
    return;

  gc_level = gc_new_level ();
  buf = alloc_buf_gc (256);
  network = print_in_addr_t (r->network, false);
  netmask = print_in_addr_t (r->netmask, false);
  gateway = print_in_addr_t (r->gateway, false);

#if defined(TARGET_LINUX)

  buf_printf (&buf, ROUTE_PATH " del -net %s netmask %s",
	      network,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: Linux route delete command failed", false);

#elif defined (WIN32)

  buf_printf (&buf, ROUTE_PATH " DELETE %s",
	      network);

  netcmd_semaphore_lock ();
  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: Windows route delete command failed", false);
  netcmd_semaphore_release ();

#elif defined (TARGET_SOLARIS)

  buf_printf (&buf, ROUTE_PATH " delete %s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: Solaris route delete command failed", false);

#elif defined(TARGET_FREEBSD)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: FreeBSD route delete command failed", false);

#elif defined(TARGET_OPENBSD)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: OpenBSD route delete command failed", false);

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

  gc_free_level (gc_level);
}
