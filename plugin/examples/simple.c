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

/*
 * This file implements a simple OpenVPN plugin module which
 * will examine the username/password provided by a client,
 * and make an accept/deny determination.
 *
 * See the README file for build instructions.
 */

#include <stdio.h>
#include <string.h>
#include "openvpn-plugin.h"
#include "mydll.h"

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
static const char *
get_env (const char *name, const char *envp[])
{
  if (envp)
    {
      int i;
      const int namelen = strlen (name);
      for (i = 0; envp[i]; ++i)
	{
	  if (!strncmp (envp[i], name, namelen))
	    {
	      const char *cp = envp[i] + namelen;
	      if (*cp == '=')
		return cp + 1;
	    }
	}
    }
  return NULL;
}

EXPORT int
plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
  /*
   * We are only interested in intercepting the
   * --auth-user-pass-verify callback.
   */
  *type_mask = PLUGIN_MASK (PLUGIN_AUTH_USER_PASS_VERIFY);
  return 0;
}

EXPORT int
plugin_func_v1 (const int type, const char *argv[], const char *envp[])
{
  /* get username/password from envp string array */
  const char *username = get_env ("username", envp);
  const char *password = get_env ("password", envp);

  /* accept username/password of foo/bar only */
  if (username && !strcmp (username, "foo")
      && password && !strcmp (password, "bar"))
    return 0;
  else
    return 1;
}

EXPORT void
plugin_close_v1 (void)
{
}
