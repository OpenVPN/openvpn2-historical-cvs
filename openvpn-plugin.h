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
 * Plug-in types.  These types correspond to the set of script callbacks
 * supported by OpenVPN.
 */
#define PLUGIN_UP                    0
#define PLUGIN_DOWN                  1
#define PLUGIN_ROUTE_UP              2
#define PLUGIN_IPCHANGE              3
#define PLUGIN_TLS_VERIFY            4
#define PLUGIN_AUTH_USER_PASS_VERIFY 5
#define PLUGIN_CLIENT_CONNECT        6
#define PLUGIN_CLIENT_DISCONNECT     7
#define PLUGIN_LEARN_ADDRESS         8
#define PLUGIN_N                     9

/*
 * Build a mask out of a set of plug-in types.
 */
#define PLUGIN_MASK(x) (1<<(x))

#ifdef PLUGIN_H

/*
 * Prototypes for functions which OpenVPN plug-ins must define.
 */

/*
 * FUNCTION: plugin_open_v1
 * 
 * Called on initial plug-in load.  OpenVPN will preserve plug-in state
 * across SIGUSR1 restarts but not across SIGHUP restarts.
 *
 * ARGUMENTS
 *
 * *type_mask : Set by OpenVPN to the logical OR of all script
 * types which this version of OpenVPN supports.  The plug-in
 * should set this value to the logical OR of all script types
 * which the plug-in wants to intercept.  For example, if the
 * script wants to intercept the client-connect and client-disconnect
 * script types, it should do this:
 *
 * *type_mask = PLUGIN_MASK(PLUGIN_CLIENT_CONNECT) | PLUGIN_MASK(PLUGIN_CLIENT_DISCONNECT)
 *
 * argv : a NULL-terminated array of options provided to the OpenVPN
 * "plug-in" directive.  argv[0] is the dynamic library pathname.
 *
 * envp : a NULL-terminated array of OpenVPN-set environmental
 * variables in "name=value" format.  Note that for security reasons,
 * these variables are not actually written to the "official" environmental
 * variable store of the process.
 *
 * RETURN VALUE
 *
 * 0 on success, nonzero on failure
 */
typedef int (*plugin_open_v1) (unsigned int *type_mask, const char *argv[], const char *envp[]);

/*
 * FUNCTION: plugin_func_v1
 *
 * Called to perform the work of a given script type.
 *
 * ARGUMENTS
 *
 * type : one of the PLUGIN_x types
 *
 * argv : a NULL-terminated array of "command line" options which
 * would normally be passed to the script.  argv[0] is the dynamic
 * library pathname.
 *
 * envp : a NULL-terminated array of OpenVPN-set environmental
 * variables in "name=value" format.  Note that for security reasons,
 * these variables are not actually written to the "official" environmental
 * variable store of the process.
 *
 * RETURN VALUE
 *
 * 0 on success, nonzero on failure
 */
typedef int (*plugin_func_v1) (const int type, const char *argv[], const char *envp[]);

/*
 * FUNCTION: plugin_close_v1
 *
 * Called immediately prior to plug-in unload.
 */
typedef void (*plugin_close_v1) (void);

#endif
