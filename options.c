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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "openvpn.h"
#include "common.h"
#include "shaper.h"
#include "crypto.h"
#include "options.h"
#include "openvpn.h"
#include "misc.h"
#include "socket.h"
#include "win32.h"

#include "memdbg.h"

const char title_string[] =
  PACKAGE_STRING
  " " TARGET_ALIAS
#ifdef USE_CRYPTO
#ifdef USE_SSL
  " [SSL]"
#else
  " [CRYPTO]"
#endif
#endif
#ifdef USE_LZO
  " [LZO]"
#endif
#ifdef USE_PTHREAD
  " [PTHREAD]"
#endif
  " built on " __DATE__
;

static const char usage_message[] =
  "%s\n"
  "\n"
  "General Options:\n"
  "--config file   : Read configuration options from file.\n"
  "--help          : Show options.\n"
  "--version       : Show copyright and version information.\n"
  "\n"
  "Tunnel Options:\n"
  "--local host    : Local host name or ip address.\n"
  "--remote host   : Remote host name or ip address.\n"
  "--proto p       : Use protocol p for communicating with peer.\n"
  "                  p = udp (default), tcp-server, or tcp-client\n"
  "--resolv-retry n: If hostname resolve fails for --remote, retry\n"
  "                  resolve for n seconds before failing (disabled by default).\n"
  "--float         : Allow remote to change its IP address/port, such as through\n"
  "                  DHCP (this is the default if --remote is not used).\n"
  "--ipchange cmd  : Execute shell command cmd on remote ip address initial\n"
  "                  setting or change -- execute as: cmd ip-address port#\n"
  "--port port     : TCP/UDP port # for both local and remote.\n"
  "--lport port    : TCP/UDP port # for local (default=%d).\n"
  "--rport port    : TCP/UDP port # for remote (default=%d).\n"
  "--nobind        : Do not bind to local address and port.\n"
  "--dev tunX|tapX : TUN/TAP device (X can be omitted for dynamic device.\n"
  "--dev-type dt   : Which device type are we using? (dt = tun or tap) Use\n"
  "                  this option only if the TUN/TAP device used with --dev\n"
  "                  does not begin with \"tun\" or \"tap\".\n"
  "--dev-node node : Explicitly set the device node rather than using\n"
  "                  /dev/net/tun, /dev/tun, /dev/tap, etc.\n"
  "--tun-ipv6      : Build tun link capable of forwarding IPv6 traffic.\n"
  "--ifconfig l rn : TUN: configure device to use IP address l as a local\n"
  "                  endpoint and rn as a remote endpoint.  l & rn should be\n"
  "                  swapped on the other peer.  l & rn must be private\n"
  "                  addresses outside of the subnets used by either peer.\n"
  "                  TAP: configure device to use IP address l as a local\n"
  "                  endpoint and rn as a subnet mask.\n"
  "--ifconfig-noexec : Don't actually execute ifconfig/netsh command, instead\n"
  "                    pass --ifconfig parms by environment to scripts.\n"
  "--route network [netmask] [gateway] [metric] :\n"
  "                  Add route to routing table after connection\n"
  "                  is established.  Multiple routes can be specified.\n"
  "                  netmask default: 255.255.255.255\n"
  "                  gateway default: taken from --route-gateway or --ifconfig\n"
  "                  Specify default by leaving blank or setting to \"nil\".\n"
  "--route-gateway gw : Specify a default gateway for use with --route.\n"
  "--route-delay n : Delay n seconds after connection initiation before\n"
  "                  adding routes (may be 0).  If not specified, routes will\n"
  "                  be added immediately after tun/tap open.\n"
  "--route-up cmd  : Execute shell cmd after routes are added.\n"
  "--route-noexec  : Don't add routes automatically.  Instead pass routes to\n"
  "                  --route-up script using environmental variables.\n"
  "--setenv name value : Set a custom environmental variable to pass to script.\n"
  "--shaper n      : Restrict output to peer to n bytes per second.\n"
  "--inactive n    : Exit after n seconds of inactivity on TUN/TAP device.\n"
  "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
  "--ping-restart n: Restart if n seconds pass without reception of remote ping.\n"
  "--ping-timer-rem: Run the --ping-exit/--ping-restart timer only if we have a\n"
  "                  remote address.\n"
  "--ping n        : Ping remote once every n seconds over TCP/UDP port.\n"
  "--persist-tun   : Keep TUN/TAP device open across SIGUSR1 or --ping-restart.\n"
  "--persist-remote-ip : Keep remote IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-local-ip  : Keep local IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-key   : Don't re-read key files across SIGUSR1 or --ping-restart.\n"
#if PASSTOS_CAPABILITY
  "--passtos       : TOS passthrough (applies to IPv4 only).\n"
#endif
  "--tun-mtu n     : Take the TUN/TAP device MTU to be n and derive the\n"
  "                  TCP/UDP MTU from it (default TAP=%d).\n"
  "--tun-mtu-extra n : Assume that TUN/TAP device might return as many\n"
  "                  as n bytes more than the tun-mtu size on read\n"
  "                  (default TUN=0 TAP=%d).\n"
  "--link-mtu n    : Take the TCP/UDP device MTU to be n and derive the tun MTU\n"
  "                  from it (default TUN=%d).\n"
  "--mtu-disc type : Should we do Path MTU discovery on TCP/UDP channel?\n"
  "                  'no'    -- Never send DF (Don't Fragment) frames\n"
  "                  'maybe' -- Use per-route hints\n"
  "                  'yes'   -- Always DF (Don't Fragment)\n"
  "--mtu-test      : Empirically measure and report MTU.\n"
#ifdef FRAGMENT_ENABLE
  "--fragment max  : Enable internal datagram fragmentation so that no UDP\n"
  "                  datagrams are sent which are larger than max bytes.\n"
  "                  Adds 4 bytes of overhead per datagram.\n"
#endif
  "--mssfix [n]    : Set upper bound on TCP MSS, default = tun-mtu size\n"
  "                  or --fragment max value, whichever is lower.\n"
  "--mlock         : Disable Paging -- ensures key material and tunnel\n"
  "                  data will never be written to disk.\n"
  "--up cmd        : Shell cmd to execute after successful tun device open.\n"
  "                  Execute as: cmd TUN/TAP-dev tun-mtu link-mtu \\\n"
  "                              ifconfig-local-ip ifconfig-remote-ip\n"
  "                  (pre --user or --group UID/GID change)\n"
  "--up-delay      : Delay TUN/TAP open and possible --up script execution\n"
  "                  until after TCP/UDP connection establishment with peer.\n"
  "--down cmd      : Shell cmd to run after tun device close.\n"
  "                  (post --user/--group UID/GID change and/or --chroot)\n"
  "                  (script parameters are same as --up option)\n"
  "--up-restart    : Run up/down scripts for all restarts including those\n"
  "                  caused by --ping-restart or SIGUSR1\n"
  "--user user     : Set UID to user after initialization.\n"
  "--group group   : Set GID to group after initialization.\n"
  "--chroot dir    : Chroot to this directory after initialization.\n"
  "--cd dir        : Change to this directory before initialization.\n"
  "--daemon [name] : Become a daemon after initialization.\n"
  "                  The optional 'name' parameter will be passed\n"
  "                  as the program name to the system logger.\n"
  "--inetd [name]  : Run as an inetd or xinetd server.  See --daemon\n"
  "                  above for a description of the 'name' parameter.\n"
  "--log file      : Output log to file which is created/truncated on open.\n"
  "--log-append file : Append log to file, or create file if nonexistent.\n"
  "--writepid file : Write main process ID to file.\n"
  "--nice n        : Change process priority (>0 = lower, <0 = higher).\n"
#ifdef USE_PTHREAD
  "--nice-work n   : Change thread priority of work thread.  The work\n"
  "                  thread is used for background processing such as\n"
  "                  RSA key number crunching.\n"
#endif
  "--verb n        : Set output verbosity to n (default=%d):\n"
  "                  (Level 3 is recommended if you want a good summary\n"
  "                  of what's happening without being swamped by output).\n"
  "                : 0 -- no output except fatal errors\n"
  "                : 1 -- startup info + connection initiated messages +\n"
  "                       non-fatal encryption & net errors\n"
  "                : 2 -- show TLS negotiations\n"
  "                : 3 -- show extra TLS info + --gremlin net outages +\n"
  "                       adaptive compress info\n"
  "                : 4 -- show parameters\n"
  "                : 5 -- show 'RrWw' chars on console for each packet sent\n"
  "                       and received from TCP/UDP (caps) or TUN/TAP (lc)\n"
  "                : 6 to 11 -- debug messages of increasing verbosity\n"
  "--mute n        : Log at most n consecutive messages in the same category.\n"
  "--gremlin       : Simulate dropped & corrupted packets + network outages\n"
  "                  to test robustness of protocol (for debugging only).\n"
  "--disable-occ   : Disable options consistency check between peers.\n"
#ifdef USE_LZO
  "--comp-lzo      : Use fast LZO compression -- may add up to 1 byte per\n"
  "                  packet for uncompressible data.\n"
  "--comp-noadapt  : Don't use adaptive compression when --comp-lzo\n"
  "                  is specified.\n"
#endif
#ifdef USE_CRYPTO
  "\n"
  "Data Channel Encryption Options (must be compatible between peers):\n"
  "(These options are meaningful for both Static Key & TLS-mode)\n"
  "--secret file   : Enable Static Key encryption mode (non-TLS),\n"
  "                  use shared secret file, generate with --genkey.\n"
  "--auth alg      : Authenticate packets with HMAC using message\n"
  "                  digest algorithm alg (default=%s).\n"
  "                  (usually adds 16 or 20 bytes per packet)\n"
  "                  Set alg=none to disable authentication.\n"
  "--cipher alg    : Encrypt packets with cipher algorithm alg\n"
  "                  (default=%s).\n"
  "                  Set alg=none to disable encryption.\n"
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  "--keysize n     : Size of cipher key in bits (optional).\n"
  "                  If unspecified, defaults to cipher-specific default.\n"
#endif
  "--no-replay     : Disable replay protection.\n"
  "--no-iv         : Disable cipher IV -- only allowed with CBC mode ciphers.\n"
  "--replay-persist file : Persist replay-protection state across sessions\n"
  "                  using file.\n"
  "--test-crypto   : Run a self-test of crypto features enabled.\n"
  "                  For debugging only.\n"
#ifdef USE_SSL
  "\n"
  "TLS Key Negotiation Options:\n"
  "(These options are meaningful only for TLS-mode)\n"
  "--tls-server    : Enable TLS and assume server role during TLS handshake.\n"
  "--tls-client    : Enable TLS and assume client role during TLS handshake.\n"
  "--ca file       : Certificate authority file in .pem format containing\n"
  "                  root certificate.\n"
  "--dh file       : File containing Diffie Hellman parameters\n"
  "                  in .pem format (for --tls-server only).\n"
  "                  Use \"openssl dhparam -out dh1024.pem 1024\" to generate.\n"
  "--cert file     : Local certificate in .pem format -- must be signed\n"
  "                  by a Certificate Authority in --ca file.\n"
  "--key file      : Local private key in .pem format.\n"
  "--tls-cipher l  : A list l of allowable TLS ciphers separated by | (optional).\n"
  "                : Use --show-tls to see a list of supported TLS ciphers.\n"
  "--tls-timeout n : Packet retransmit timeout on TLS control channel\n"
  "                  if no ACK from remote within n seconds (default=%d).\n"
  "--reneg-bytes n : Renegotiate data chan. key after n bytes sent and recvd.\n"
  "--reneg-pkts n  : Renegotiate data chan. key after n packets sent and recvd.\n"
  "--reneg-sec n   : Renegotiate data chan. key after n seconds (default=%d).\n"
  "--hand-window n : Data channel key exchange must finalize within n seconds\n"
  "                  of handshake initiation by any peer (default=%d).\n"
  "--tran-window n : Transition window -- old key can live this many seconds\n"
  "                  after new key renegotiation begins (default=%d).\n"
  "--single-session: Allow only one session (reset state on restart).\n"
  "--tls-auth f    : Add an additional layer of authentication on top of the TLS\n"
  "                  control channel to protect against DoS attacks.\n"
  "                  f (required) is a shared-secret passphrase file.\n"
  "--askpass       : Get PEM password from controlling tty before we daemonize.\n"
  "--tls-verify cmd: Execute shell command cmd to verify the X509 name of a\n"
  "                  pending TLS connection that has otherwise passed all other\n"
  "                  tests of certification.  cmd should return 0 to allow\n"
  "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
  "                  executed as 'cmd certificate_depth X509_NAME_oneline')\n"
#endif				/* USE_SSL */
  "\n"
  "SSL Library information:\n"
  "--show-ciphers  : Show cipher algorithms to use with --cipher option.\n"
  "--show-digests  : Show message digest algorithms to use with --auth option.\n"
#ifdef USE_SSL
  "--show-tls      : Show all TLS ciphers (TLS used only as a control channel).\n"
#endif
#ifdef WIN32
  "\n"
  "Windows Specific:\n"
  "--show-adapters : Show all TAP-Win32 adapters.\n"
  "--ip-win32 method : When using --ifconfig on Windows, set TAP-Win32 adapter\n"
  "                    IP address using method = manual, netsh, ipapi, or\n"
  "                    dynamic (default = ipapi).\n"
  "--tap-sleep n   : Sleep for n seconds after TAP adapter open before\n"
  "                  attempting to set adapter properties.\n"
  "--show-valid-subnets : Show valid subnets for --dev tun emulation.\n" 
  "--pause-exit    : When run from a console window, pause before exiting.\n"
#endif
  "\n"
  "Generate a random key (only for non-TLS static key encryption mode):\n"
  "--genkey        : Generate a random key to be used as a shared secret,\n"
  "                  for use with the --secret option.\n"
  "--secret file   : Write key to file.\n"
#endif				/* USE_CRYPTO */
#ifdef TUNSETPERSIST
  "\n"
  "TUN/TAP config mode (available with linux 2.4+):\n"
  "--mktun         : Create a persistent tunnel.\n"
  "--rmtun         : Remove a persistent tunnel.\n"
  "--dev tunX|tapX : TUN/TAP device\n"
  "--dev-type dt   : Device type.  See tunnel options above for details.\n"
#endif
 ;

/*
 * This is where the options defaults go.
 * Any option not explicitly set here
 * will be set to 0.
 */
void
init_options (struct options *o)
{
  CLEAR (*o);
  o->proto = PROTO_UDPv4;
#ifdef TUNSETPERSIST
  o->persist_mode = 1;
#endif
  o->local_port = o->remote_port = 5000;
  o->verbosity = 1;
  o->bind_local = true;
  o->tun_mtu = TUN_MTU_DEFAULT;
  o->link_mtu = LINK_MTU_DEFAULT;
  o->mtu_discover_type = -1;
  o->occ = true;
#ifdef FRAGMENT_ENABLE
  o->mtu_icmp = true;
#endif
#ifdef USE_LZO
  o->comp_lzo_adaptive = true;
#endif
#ifdef WIN32
  o->tuntap_flags = (IP_SET_IPAPI & IP_SET_MASK);
#endif
#ifdef USE_CRYPTO
  o->ciphername = "BF-CBC";
  o->ciphername_defined = true;
  o->authname = "SHA1";
  o->authname_defined = true;
  o->packet_id = true;
  o->use_iv = true;
#ifdef USE_SSL
  o->tls_timeout = 2;
  o->renegotiate_seconds = 3600;
  o->handshake_window = 60;
  o->transition_window = 3600;
#endif
#endif
}

#define SHOW_PARM(name, value, format) msg(D_SHOW_PARMS, "  " #name " = " format, (value))
#define SHOW_STR(var)  SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_INT(var)  SHOW_PARM(var, o->var, "%d")
#define SHOW_UINT(var)  SHOW_PARM(var, o->var, "%u")
#define SHOW_UNSIGNED(var)  SHOW_PARM(var, o->var, "0x%08x")
#define SHOW_BOOL(var) SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

void
setenv_settings (const struct options *o)
{
  setenv_str ("config", o->config);
  setenv_str ("proto", proto2ascii (o->proto, false));
  setenv_str ("local", o->local);
  setenv_int ("local_port", o->local_port);
  setenv_str ("remote", o->remote);
  setenv_int ("remote_port", o->remote_port);
}

void
show_settings (const struct options *o)
{
  msg (D_SHOW_PARMS, "Current Parameter Settings:");

  SHOW_STR (config);

#ifdef TUNSETPERSIST
  SHOW_BOOL (persist_config);
  SHOW_INT (persist_mode);
#endif

#ifdef USE_CRYPTO
  SHOW_BOOL (show_ciphers);
  SHOW_BOOL (show_digests);
  SHOW_BOOL (genkey);
#ifdef USE_SSL
  SHOW_BOOL (askpass);
  SHOW_BOOL (show_tls_ciphers);
#endif
#endif

  SHOW_INT (proto);
  SHOW_STR (local);
  SHOW_STR (remote);

  SHOW_INT (local_port);
  SHOW_INT (remote_port);
  SHOW_BOOL (remote_float);
  SHOW_STR (ipchange);
  SHOW_BOOL (bind_local);
  SHOW_STR (dev);
  SHOW_STR (dev_type);
  SHOW_STR (dev_node);
  SHOW_BOOL (tun_ipv6);
  SHOW_STR (ifconfig_local);
  SHOW_STR (ifconfig_remote_netmask);
  SHOW_BOOL (ifconfig_noexec);
#ifdef HAVE_GETTIMEOFDAY
  SHOW_INT (shaper);
#endif
  SHOW_INT (tun_mtu);
  SHOW_BOOL (tun_mtu_defined);
  SHOW_INT (link_mtu);
  SHOW_BOOL (link_mtu_defined);
  SHOW_INT (tun_mtu_extra);
  SHOW_BOOL (tun_mtu_extra_defined);
#ifdef FRAGMENT_ENABLE
  SHOW_BOOL (mtu_dynamic);
  SHOW_INT (mtu_min);
  SHOW_BOOL (mtu_min_defined);
  SHOW_INT (mtu_max);
  SHOW_BOOL (mtu_max_defined);
  SHOW_BOOL (mtu_icmp);
#endif
  SHOW_INT (mtu_discover_type);
  SHOW_INT (mtu_test);

  SHOW_BOOL (mlock);
  SHOW_INT (inactivity_timeout);
  SHOW_INT (ping_send_timeout);
  SHOW_INT (ping_rec_timeout);
  SHOW_INT (ping_rec_timeout_action);
  SHOW_BOOL (ping_timer_remote);

  SHOW_BOOL (persist_tun);
  SHOW_BOOL (persist_local_ip);
  SHOW_BOOL (persist_remote_ip);
  SHOW_BOOL (persist_key);

  SHOW_BOOL (mssfix_defined);
  SHOW_INT (mssfix);
  
#if PASSTOS_CAPABILITY
  SHOW_BOOL (passtos);
#endif

  SHOW_INT (resolve_retry_seconds);

  SHOW_STR (username);
  SHOW_STR (groupname);
  SHOW_STR (chroot_dir);
  SHOW_STR (cd_dir);
  SHOW_STR (writepid);
  SHOW_STR (up_script);
  SHOW_STR (down_script);
  SHOW_BOOL (up_restart);
  SHOW_BOOL (daemon);
  SHOW_BOOL (inetd);
  SHOW_BOOL (log);
  SHOW_INT (nice);
  SHOW_INT (verbosity);
  SHOW_INT (mute);
  SHOW_BOOL (gremlin);
  SHOW_UINT (tuntap_flags);

  SHOW_BOOL (occ);

#ifdef USE_LZO
  SHOW_BOOL (comp_lzo);
  SHOW_BOOL (comp_lzo_adaptive);
#endif

  SHOW_STR (route_script);
  SHOW_STR (route_default_gateway);
  SHOW_BOOL (route_noexec);
  SHOW_INT (route_delay);
  SHOW_BOOL (route_delay_defined);
  print_route_options (&o->routes, D_SHOW_PARMS);

#ifdef USE_CRYPTO
  SHOW_STR (shared_secret_file);
  SHOW_BOOL (ciphername_defined);
  SHOW_STR (ciphername);
  SHOW_BOOL (authname_defined);
  SHOW_STR (authname);
  SHOW_INT (keysize);
  SHOW_BOOL (packet_id);
  SHOW_STR (packet_id_file);
  SHOW_BOOL (use_iv);
  SHOW_BOOL (test_crypto);

#ifdef USE_SSL
  SHOW_BOOL (tls_server);
  SHOW_BOOL (tls_client);
  SHOW_STR (ca_file);
  SHOW_STR (dh_file);
  SHOW_STR (cert_file);
  SHOW_STR (priv_key_file);
  SHOW_STR (cipher_list);
  SHOW_STR (tls_verify);

  SHOW_INT (tls_timeout);

  SHOW_INT (renegotiate_bytes);
  SHOW_INT (renegotiate_packets);
  SHOW_INT (renegotiate_seconds);

  SHOW_INT (handshake_window);
  SHOW_INT (transition_window);

  SHOW_BOOL (single_session);

  SHOW_STR (tls_auth_file);
#endif
#endif
}

#undef SHOW_PARM
#undef SHOW_STR
#undef SHOW_INT
#undef SHOW_BOOL

/*
 * Build an options string to represent data channel encryption options.
 * This string must match exactly between peers.  The keysize is checked
 * separately by read_key().
 *
 * The following options must match on both peers:
 *
 * Tunnel options:
 *
 * --dev tun|tap [unit number need not match]
 * --dev-type tun|tap
 * --link-mtu
 * --udp-mtu
 * --tun-mtu
 * --proto udp
 * --proto tcp-client [matched with --proto tcp-server
 *                     on the other end of the connection]
 * --proto tcp-server [matched with --proto tcp-client on
 *                     the other end of the connection]
 * --tun-ipv6
 * --ifconfig x y [matched with --ifconfig y x on
 *                 the other end of the connection]
 *
 * --comp-lzo
 * --mtu-dynamic
 *
 * Crypto Options:
 *
 * --cipher
 * --auth
 * --keysize
 * --secret
 * --no-replay
 * --no-iv
 *
 * SSL Options:
 *
 * --tls-auth
 * --tls-client [matched with --tls-server on
 *               the other end of the connection]
 * --tls-server [matched with --tls-client on
 *               the other end of the connection]
 */

char *
options_string (const struct options *o,
		const struct frame *frame,
		const struct tuntap *tt,
		bool remote)
{
  struct buffer out = alloc_buf (256);

  buf_printf (&out, "V3");

  /*
   * Tunnel Options
   */

  buf_printf (&out, ",dev-type %s", dev_type_string (o->dev, o->dev_type));
  buf_printf (&out, ",link-mtu %d", MAX_RW_SIZE_LINK(frame));
  buf_printf (&out, ",tun-mtu %d", MAX_RW_SIZE_TUN(frame));
  buf_printf (&out, ",proto %s", proto2ascii (proto_remote (o->proto, remote), true));
  if (o->tun_ipv6)
    buf_printf (&out, ",tun-ipv6");
  if (tt)
    buf_printf (&out, ",ifconfig %s", ifconfig_options_string (tt, remote));

#ifdef USE_LZO
  if (o->comp_lzo)
    buf_printf (&out, ",comp-lzo");
#endif

#ifdef FRAGMENT_ENABLE
  if (o->mtu_dynamic)
    buf_printf (&out, ",mtu-dynamic");
#endif

#ifdef USE_CRYPTO

#ifdef USE_SSL
#define TLS_CLIENT (o->tls_client)
#define TLS_SERVER (o->tls_server)
#else
#define TLS_CLIENT (false)
#define TLS_SERVER (false)
#endif

  /*
   * Crypto Options
   */
    if (o->shared_secret_file || TLS_CLIENT || TLS_SERVER)
      {
	struct key_type kt;

	ASSERT ((o->shared_secret_file != NULL)
		+ (TLS_CLIENT == true)
		+ (TLS_SERVER == true)
		<= 1);

	init_key_type (&kt, o->ciphername, o->ciphername_defined,
		       o->authname, o->authname_defined,
		       o->keysize, true, false);

	buf_printf (&out, ",cipher %s", kt_cipher_name (&kt));
	buf_printf (&out, ",auth %s", kt_digest_name (&kt));
	buf_printf (&out, ",keysize %d", kt_key_size (&kt));
	if (o->shared_secret_file)
	  buf_printf (&out, ",secret");
	if (!o->packet_id)
	  buf_printf (&out, ",no-replay");
	if (!o->use_iv)
	  buf_printf (&out, ",no-iv");
      }

#ifdef USE_SSL
  /*
   * SSL Options
   */
  {
    if (o->tls_auth_file)
	buf_printf (&out, ",tls-auth");

    if (remote)
      {
	if (TLS_CLIENT)
	  buf_printf (&out, ",tls-server");
	else if (TLS_SERVER)
	  buf_printf (&out, ",tls-client");
      }
    else
      {
	if (TLS_CLIENT)
	  buf_printf (&out, ",tls-client");
	else if (TLS_SERVER)
	  buf_printf (&out, ",tls-server");
      }
  }
#endif /* USE_SSL */

#undef TLS_CLIENT
#undef TLS_SERVER

#endif /* USE_CRYPTO */

  return BSTR (&out);
}

/*
 * Compare option strings for equality.
 * If the first two chars of the strings differ, it means that
 * we are looking at different versions of the options string,
 * therefore don't compare them and return true.
 */
bool
options_cmp_equal (char *actual, const char *expected, size_t actual_n)
{
  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
#ifndef STRICT_OPTIONS_CHECK
      if (strncmp (actual, expected, 2))
	{
	  msg (D_SHOW_OCC, "NOTE: failed to perform options consistency check between peers because of OpenVPN version differences -- you can disable the options consistency check with --disable-occ (Required for TLS connections between OpenVPN 1.3.x and later versions).  Actual Remote Options: '%s'.  Expected Remote Options: '%s'", actual, expected);
	  return true;
	}
      else
#endif
	return !strcmp (actual, expected);
    }
  else
    return true;
}

void
options_warning (char *actual, const char *expected, size_t actual_n)
{
  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
      msg (M_WARN,
	   "WARNING: Actual Remote Options ('%s') are inconsistent with Expected Remote Options ('%s')",
	   actual,
	   expected);
    }
}

const char *
options_string_version (const char* s)
{
  struct buffer out = alloc_buf (4);
  strncpynt (BPTR (&out), s, 3);
  return BSTR (&out);
}

static char *
comma_to_space (const char *src)
{
  char *ret = (char *) gc_malloc (strlen (src) + 1);
  char *dest = ret;
  char c;

  do
    {
      c = *src++;
      if (c == ',')
	c = ' ';
      *dest++ = c;
    }
  while (c);
  return ret;
}

static void
usage (void)
{
  struct options o;
  FILE *fp = msg_fp();

  init_options (&o);

#if defined(USE_CRYPTO) && defined(USE_SSL)
  fprintf (fp, usage_message,
	   title_string, o.local_port, o.remote_port,
	   TAP_MTU_DEFAULT, o.tun_mtu_extra, o.link_mtu,
	   o.verbosity,
	   o.authname, o.ciphername,
	   o.tls_timeout, o.renegotiate_seconds,
	   o.handshake_window, o.transition_window);
#elif defined(USE_CRYPTO)
  fprintf (fp, usage_message,
	   title_string, o.local_port, o.remote_port,
	   TAP_MTU_DEFAULT, o.tun_mtu_extra, o.link_mtu,
	   o.verbosity,
	   o.authname, o.ciphername);
#else
  fprintf (fp, usage_message,
	   title_string, o.local_port, o.remote_port,
	   TAP_MTU_DEFAULT, o.tun_mtu_extra, o.link_mtu,
	   o.verbosity);
#endif
  fflush(fp);
  
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
usage_small (void)
{
  msg (M_WARN|M_NOPREFIX, "Use --help for more information.");
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

static void
usage_version (void)
{
  msg (M_INFO|M_NOPREFIX, "%s", title_string);
  msg (M_INFO|M_NOPREFIX, "Copyright (C) 2002-2003 James Yonan <jim@yonan.net>");
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
notnull (const char *arg, const char *description)
{
  if (!arg)
    {
      msg (M_WARN|M_NOPREFIX, "Options error: You must define %s", description);
      usage_small ();
    }
}

bool
string_defined_equal (const char *s1, const char *s2)
{
  if (s1 && s2)
    return !strcmp (s1, s2);
  else
    return false;
}

static void
ping_rec_err (void)
{
  msg (M_WARN|M_NOPREFIX, "Options error: only one of --ping-exit or --ping-restart options may be specified");
  usage_small ();
}

static int
positive (int i)
{
  return i < 0 ? 0 : i;
}

static bool
space (char c)
{
  return c == '\0' || isspace (c);
}

static int
parse_line (char *line, char *p[], int n, const char *file, int line_num)
{
  int ret = 0;
  char *c = line;
  char *start = NULL;

  /*
   * Parse states:
   * 0 -- Initial
   * 1 -- Reading non-quoted parm
   * 2 -- Leading quote
   * 3 -- Reading quoted parm
   * 4 -- First char after parm
   */
  int state = 0;

  do
    {
      if (state == 0)
	{
	  if (!space (*c))
	    {
	      if (*c == ';' || *c == '#') /* comment */
		break;
	      if (*c == '\"')
		state = 2;
	      else
		{
		  start = c;
		  state = 1;
		}
	    }
	}
      else if (state == 1)
	{
	  if (space (*c))
	    state = 4;
	}
      else if (state == 2)
	{
	  start = c;
	  state = 3;
	}
      else if (state == 3)
	{
	  if (*c == '\"')
	    state = 4;
	}
      if (state == 4)
	{
	  const int len = (int) (c - start);
	  ASSERT (len > 0);
	  p[ret] = gc_malloc (len + 1);
	  memcpy (p[ret], start, len);
	  p[ret][len] = '\0';
	  state = 0;
	  if (++ret >= n)
	    break;
	}
    } while (*c++ != '\0');

  if (state == 2 || state == 3)
	msg (M_FATAL, "No closing quotation (\") in %s:%d", file, line_num);
  if (state)
	msg (M_FATAL, "Residual parse state (%d) in %s:%d", state, file, line_num);
#if 0
  {
    int i;
    for (i = 0; i < ret; ++i)
      {
	msg (M_INFO, "%s:%d ARG[%d] '%s'", file, line_num, i, p[i]);
      }
  }
#endif
    return ret;
}

static int
add_option (struct options *options, int i, char *p[],
	    const char* file, int line, int level);

static void
read_config_file (struct options *options, const char* file, int level,
		  const char* top_file, int top_line)
{
  const int max_recursive_levels = 10;
  FILE *fp;
  int line_num;
  char line[256];

  ++level;
  if (level > max_recursive_levels)
    msg (M_FATAL, "In %s:%d: Maximum recursive include levels exceeded in include attempt of file %s -- probably you have a configuration file that tries to include itself.", top_file, top_line, file);

  fp = fopen (file, "r");
  if (!fp)
    msg (M_ERR, "In %s:%d: Error opening configuration file: %s", top_file, top_line, file);

  line_num = 0;
  while (fgets(line, sizeof (line), fp))
    {
      char *p[MAX_PARMS];
      CLEAR (p);
      ++line_num;
      if (parse_line (line, p, SIZE (p), file, line_num))
	{
	  if (strlen (p[0]) >= 3 && !strncmp (p[0], "--", 2))
	    p[0] += 2;
	  add_option (options, 0, p, file, line_num, level);
	}
    }
  fclose (fp);
}

void
parse_argv (struct options* options, int argc, char *argv[])
{
  int i, j;

  /* usage message */
  if (argc <= 1)
    usage ();

  /* parse command line */
  for (i = 1; i < argc; ++i)
    {
      char *p[MAX_PARMS];
      CLEAR (p);
      p[0] = argv[i];
      if (strncmp(p[0], "--", 2))
	{
	  msg (M_WARN|M_NOPREFIX, "I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--'", p[0]);
	  usage_small ();
	}
      p[0] += 2;

      for (j = 1; j < MAX_PARMS; ++j)
	{
	  if (i + j < argc)
	    {
	      char *arg = argv[i + j];
	      if (strncmp (arg, "--", 2))
		p[j] = arg;
	      else
		break;
	    }
	}
      i = add_option (options, i, p, NULL, 0, 0);
    }
}

static int
add_option (struct options *options, int i, char *p[],
	    const char* file, int line, int level)
{
  ASSERT (MAX_PARMS >= 5);

  if (!file)
    {
      file = "[CMD-LINE]";
      line = 1;
    }
  if (streq (p[0], "help"))
    {
      usage ();
    }
  if (streq (p[0], "version"))
    {
      usage_version ();
    }
  else if (streq (p[0], "config") && p[1])
    {
      ++i;

      /* save first config file only in options */
      if (!options->config)
	options->config = p[1];

      read_config_file (options, p[1], level, file, line);
    }
  else if (streq (p[0], "dev") && p[1])
    {
      ++i;
      options->dev = p[1];
    }
  else if (streq (p[0], "dev-type") && p[1])
    {
      ++i;
      options->dev_type = p[1];
    }
  else if (streq (p[0], "dev-node") && p[1])
    {
      ++i;
      options->dev_node = p[1];
    }
  else if (streq (p[0], "tun-ipv6"))
    {
      options->tun_ipv6 = true;
    }
  else if (streq (p[0], "ifconfig") && p[1] && p[2])
    {
      options->ifconfig_local = p[1];
      options->ifconfig_remote_netmask = p[2];
      i += 2;
    }
  else if (streq (p[0], "ifconfig-noexec"))
    {
      options->ifconfig_noexec = true;
    }
  else if (streq (p[0], "local") && p[1])
    {
      ++i;
      options->local = p[1];
    }
  else if (streq (p[0], "remote") && p[1])
    {
      ++i;
      options->remote = p[1];
    }
  else if (streq (p[0], "resolv-retry") && p[1])
    {
      ++i;
      options->resolve_retry_seconds = positive (atoi (p[1]));
    }
  else if (streq (p[0], "ipchange") && p[1])
    {
      ++i;
      options->ipchange = comma_to_space (p[1]);
    }
  else if (streq (p[0], "float"))
    {
      options->remote_float = true;
    }
  else if (streq (p[0], "gremlin"))
    {
      options->gremlin = true;
    }
  else if (streq (p[0], "user") && p[1])
    {
      ++i;
      options->username = p[1];
    }
  else if (streq (p[0], "group") && p[1])
    {
      ++i;
      options->groupname = p[1];
    }
  else if (streq (p[0], "chroot") && p[1])
    {
      ++i;
      options->chroot_dir = p[1];
    }
  else if (streq (p[0], "cd") && p[1])
    {
      ++i;
      options->cd_dir = p[1];
      if (openvpn_chdir (p[1]))
	msg (M_ERR, "cd to '%s' failed", p[1]);
    }
  else if (streq (p[0], "writepid") && p[1])
    {
      ++i;
      options->writepid = p[1];
    }
  else if (streq (p[0], "up") && p[1])
    {
      ++i;
      options->up_script = p[1];
    }
  else if (streq (p[0], "down") && p[1])
    {
      ++i;
      options->down_script = p[1];
    }
  else if (streq (p[0], "up-delay"))
    {
      options->up_delay = true;
    }
  else if (streq (p[0], "up-restart"))
    {
      options->up_restart = true;
    }
  else if (streq (p[0], "daemon"))
    {
      if (!options->daemon) {
	options->daemon = true;
	open_syslog (p[1]);
	if (p[1])
	  ++i;
      }
    }
  else if (streq (p[0], "inetd"))
    {
      if (!options->inetd)
	{
	  options->inetd = true;
	  save_inetd_socket_descriptor ();
	  open_syslog (p[1]);
	  if (p[1])
	    ++i;
	}
    }
  else if (streq (p[0], "log") && p[1])
    {
      ++i;
      options->log = true;
      redirect_stdout_stderr (p[1], false);
    }
  else if (streq (p[0], "log-append") && p[1])
    {
      ++i;
      options->log = true;
      redirect_stdout_stderr (p[1], true);
    }
  else if (streq (p[0], "mlock"))
    {
      options->mlock = true;
    }
  else if (streq (p[0], "verb") && p[1])
    {
      ++i;
      options->verbosity = positive (atoi (p[1]));
    }
  else if (streq (p[0], "mute") && p[1])
    {
      ++i;
      options->mute = positive (atoi (p[1]));
    }
  else if ((streq (p[0], "link-mtu") || streq (p[0], "udp-mtu")) && p[1])
    {
      ++i;
      options->link_mtu = positive (atoi (p[1]));
      options->link_mtu_defined = true;
    }
  else if (streq (p[0], "tun-mtu") && p[1])
    {
      ++i;
      options->tun_mtu = positive (atoi (p[1]));
      options->tun_mtu_defined = true;
    }
  else if (streq (p[0], "tun-mtu-extra") && p[1])
    {
      ++i;
      options->tun_mtu_extra = positive (atoi (p[1]));
      options->tun_mtu_extra_defined = true;
    }
#ifdef FRAGMENT_ENABLE
  else if (streq (p[0], "mtu-dynamic"))
    {
      options->mtu_dynamic = true;
      if (p[1])
	{
	  if ((options->mtu_min = positive (atoi (p[1]))))
	    options->mtu_min_defined = true;
	  ++i;
	}
      if (p[2])
	{
	  if ((options->mtu_max = positive (atoi (p[2]))))
	    options->mtu_max_defined = true;
	  ++i;
	}
    }
  else if (streq (p[0], "mtu-noicmp"))
    {
      options->mtu_icmp = false;
    }
  else if (streq (p[0], "fragment") && p[1])
    {
      ++i;
      options->mtu_dynamic = true;
      options->mtu_max = positive (atoi (p[1]));
      options->mtu_max_defined = true;
    }
#endif
  else if (streq (p[0], "mtu-disc") && p[1])
    {
      ++i;
      options->mtu_discover_type = translate_mtu_discover_type_name (p[1]);
    }
  else if (streq (p[0], "mtu-test"))
    {
      options->mtu_test = true;
    }
  else if (streq (p[0], "nice") && p[1])
    {
      ++i;
      options->nice = atoi (p[1]);
    }
#ifdef USE_PTHREAD
  else if (streq (p[0], "nice-work") && p[1])
    {
      ++i;
      options->nice_work = atoi (p[1]);
    }
#endif
  else if (streq (p[0], "shaper") && p[1])
    {
#ifdef HAVE_GETTIMEOFDAY
      ++i;
      options->shaper = atoi (p[1]);
      if (options->shaper < SHAPER_MIN || options->shaper > SHAPER_MAX)
	{
	  msg (M_WARN, "bad shaper value, must be between %d and %d",
	       SHAPER_MIN, SHAPER_MAX);
	  usage_small ();
	}
#else /* HAVE_GETTIMEOFDAY */
      msg (M_WARN, "--shaper requires the gettimeofday() function which is missing");
      usage_small ();
#endif /* HAVE_GETTIMEOFDAY */
    }
  else if (streq (p[0], "port") && p[1])
    {
      ++i;
      options->local_port = options->remote_port = atoi (p[1]);
      if (options->local_port <= 0 || options->remote_port <= 0)
	{
	  msg (M_WARN, "Bad port number: %s", p[1]);
	  usage_small ();
	}
    }
  else if (streq (p[0], "lport") && p[1])
    {
      ++i;
      options->local_port = atoi (p[1]);
      if (options->local_port <= 0)
	{
	  msg (M_WARN, "Bad local port number: %s", p[1]);
	  usage_small ();
	}
    }
  else if (streq (p[0], "rport") && p[1])
    {
      ++i;
      options->remote_port = atoi (p[1]);
      if (options->remote_port <= 0)
	{
	  msg (M_WARN, "Bad remote port number: %s", p[1]);
	  usage_small ();
	}
    }
  else if (streq (p[0], "nobind"))
    {
      options->bind_local = false;
    }
  else if (streq (p[0], "inactive") && p[1])
    {
      ++i;
      options->inactivity_timeout = positive (atoi (p[1]));
    }
  else if (streq (p[0], "proto") && p[1])
    {
      ++i;
      options->proto = ascii2proto (p[1]);
      if (options->proto < 0)
	{
	  msg (M_WARN, "Bad protocol: '%s'.  Allowed protocols with --proto option: %s",
	       p[1],
	       proto2ascii_all());
	  usage_small ();
	}
    }
  else if (streq (p[0], "ping") && p[1])
    {
      ++i;
      options->ping_send_timeout = positive (atoi (p[1]));
    }
  else if (streq (p[0], "ping-exit") && p[1])
    {
      ++i;
      if (options->ping_rec_timeout_action)
	ping_rec_err();
      options->ping_rec_timeout = positive (atoi (p[1]));
      options->ping_rec_timeout_action = PING_EXIT;
    }
  else if (streq (p[0], "ping-restart") && p[1])
    {
      ++i;
      if (options->ping_rec_timeout_action)
	ping_rec_err();
      options->ping_rec_timeout = positive (atoi (p[1]));
      options->ping_rec_timeout_action = PING_RESTART;
    }
  else if (streq (p[0], "ping-timer-rem"))
    {
      options->ping_timer_remote = true;
    }
  else if (streq (p[0], "persist-tun"))
    {
      options->persist_tun = true;
    }
  else if (streq (p[0], "persist-key"))
    {
      options->persist_key = true;
    }
  else if (streq (p[0], "persist-local-ip"))
    {
      options->persist_local_ip = true;
    }
  else if (streq (p[0], "persist-remote-ip"))
    {
      options->persist_remote_ip = true;
    }
  else if (streq (p[0], "route") && p[1])
    {
      ++i;
      if (p[2])
	++i;
      if (p[3])
	++i;
      if (p[4])
	++i;
      add_route_to_option_list (&options->routes, p[1], p[2], p[3], p[4]);
    }
  else if (streq (p[0], "route-gateway") && p[1])
    {
      ++i;
      options->route_default_gateway = p[1];      
    }
  else if (streq (p[0], "route-delay"))
    {
      options->route_delay_defined = true;
      if (p[1])
	{
	  ++i;
	  options->route_delay = positive (atoi (p[1]));
	}
      else
	{
	  options->route_delay = 0;
	}
    }
  else if (streq (p[0], "route-up") && p[1])
    {
      ++i;
      options->route_script = p[1];
    }
  else if (streq (p[0], "route-noexec"))
    {
      options->route_noexec = true;
    }
  else if (streq (p[0], "setenv") && p[1] && p[2])
    {
      i += 2;
      setenv_str (p[1], p[2]);
    }
  else if (streq (p[0], "mssfix"))
    {
      options->mssfix_defined = true;
      if (p[1])
	{
	  ++i;
	  options->mssfix = positive (atoi (p[1]));
	}
    }
  else if (streq (p[0], "disable-occ"))
    {
      options->occ = false;
    }
#ifdef WIN32
  else if (streq (p[0], "ip-win32") && p[1])
    {
      const int index = ascii2ipset (p[1]);
      ++i;
      if (index < 0)
	{
	  msg (M_WARN|M_NOPREFIX,
	       "Bad --ip-win32 method: '%s'.  Allowed methods: %s",
	       p[1],
	       ipset2ascii_all());
	  usage_small ();
	}

#if 1
      if (index == IP_SET_DHCP)
	msg (M_FATAL|M_NOPREFIX, "Sorry but '--ip-win32 dynamic' has not been implemented yet -- try one of the other three methods.");
#endif

      options->tuntap_flags &= ~IP_SET_MASK;
      options->tuntap_flags |= (index & IP_SET_MASK);
    }
  else if (streq (p[0], "show-adapters"))
    {
      show_tap_win32_adapters ();
      openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
    }
  else if (streq (p[0], "tap-sleep") && p[1])
    {
      int s;
      ++i;
      s = atoi (p[1]);
      if (s < 0 || s >= 256)
	msg (M_FATAL, "--tap-sleep parameter must be between 0 and 255");
      options->tuntap_flags &= ~(TUNTAP_SLEEP_MASK << TUNTAP_SLEEP_SHIFT);
      options->tuntap_flags |= (s << TUNTAP_SLEEP_SHIFT);
    }
  else if (streq (p[0], "show-valid-subnets"))
    {
      show_valid_win32_tun_subnets ();
      openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
    }
  else if (streq (p[0], "pause-exit"))
    {
      set_pause_exit_win32 ();
    }
#endif
#if PASSTOS_CAPABILITY
  else if (streq (p[0], "passtos"))
    {
      options->passtos = true;
    }
#endif
#ifdef USE_LZO
  else if (streq (p[0], "comp-lzo"))
    {
      options->comp_lzo = true;
    }
  else if (streq (p[0], "comp-noadapt"))
    {
      options->comp_lzo_adaptive = false;
    }
#endif /* USE_LZO */
#ifdef USE_CRYPTO
  else if (streq (p[0], "show-ciphers"))
    {
      options->show_ciphers = true;
    }
  else if (streq (p[0], "show-digests"))
    {
      options->show_digests = true;
    }
  else if (streq (p[0], "secret") && p[1])
    {
      ++i;
      options->shared_secret_file = p[1];
    }
  else if (streq (p[0], "genkey"))
    {
      options->genkey = true;
    }
  else if (streq (p[0], "auth") && p[1])
    {
      ++i;
      options->authname_defined = true;
      options->authname = p[1];
      if (streq (options->authname, "none"))
	{
	  options->authname_defined = false;
	  options->authname = NULL;
	}
    }
  else if (streq (p[0], "auth"))
    {
      options->authname_defined = true;
    }
  else if (streq (p[0], "cipher") && p[1])
    {
      ++i;
      options->ciphername_defined = true;
      options->ciphername = p[1];
      if (streq (options->ciphername, "none"))
	{
	  options->ciphername_defined = false;
	  options->ciphername = NULL;
	}
    }
  else if (streq (p[0], "cipher"))
    {
      options->ciphername_defined = true;
    }
  else if (streq (p[0], "no-replay"))
    {
      options->packet_id = false;
    }
  else if (streq (p[0], "no-iv"))
    {
      options->use_iv = false;
    }
  else if (streq (p[0], "replay-persist") && p[1])
    {
      ++i;
      options->packet_id_file = p[1];
    }
  else if (streq (p[0], "test-crypto"))
    {
      options->test_crypto = true;
    }
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  else if (streq (p[0], "keysize") && p[1])
    {
      ++i;
      options->keysize = atoi (p[1]) / 8;
      if (options->keysize < 0 || options->keysize > MAX_CIPHER_KEY_LENGTH)
	{
	  msg (M_WARN, "Bad keysize: %s", p[1]);
	  usage_small ();
	}
    }
#endif
#ifdef USE_SSL
  else if (streq (p[0], "show-tls"))
    {
      options->show_tls_ciphers = true;
    }
  else if (streq (p[0], "tls-server"))
    {
      options->tls_server = true;
    }
  else if (streq (p[0], "tls-client"))
    {
      options->tls_client = true;
    }
  else if (streq (p[0], "ca") && p[1])
    {
      ++i;
      options->ca_file = p[1];
    }
  else if (streq (p[0], "dh") && p[1])
    {
      ++i;
      options->dh_file = p[1];
    }
  else if (streq (p[0], "cert") && p[1])
    {
      ++i;
      options->cert_file = p[1];
    }
  else if (streq (p[0], "key") && p[1])
    {
      ++i;
      options->priv_key_file = p[1];
    }
  else if (streq (p[0], "askpass"))
    {
      options->askpass = true;
    }
  else if (streq (p[0], "single-session"))
    {
      options->single_session = true;
    }
  else if (streq (p[0], "tls-cipher") && p[1])
    {
      ++i;
      options->cipher_list = p[1];
    }
  else if (streq (p[0], "tls-verify") && p[1])
    {
      ++i;
      options->tls_verify = comma_to_space (p[1]);
    }
  else if (streq (p[0], "tls_timeout") && p[1])
    {
      ++i;
      options->tls_timeout = positive (atoi (p[1]));
    }
  else if (streq (p[0], "reneg-bytes") && p[1])
    {
      ++i;
      options->renegotiate_bytes = positive (atoi (p[1]));
    }
  else if (streq (p[0], "reneg-pkts") && p[1])
    {
      ++i;
      options->renegotiate_packets = positive (atoi (p[1]));
    }
  else if (streq (p[0], "reneg-sec") && p[1])
    {
      ++i;
      options->renegotiate_seconds = positive (atoi (p[1]));
    }
  else if (streq (p[0], "hand-window") && p[1])
    {
      ++i;
      options->handshake_window = positive (atoi (p[1]));
    }
  else if (streq (p[0], "tran-window") && p[1])
    {
      ++i;
      options->transition_window = positive (atoi (p[1]));
    }
  else if (streq (p[0], "tls-auth") && p[1])
    {
      ++i;
      options->tls_auth_file = p[1];
    }
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
#ifdef TUNSETPERSIST
  else if (streq (p[0], "rmtun"))
    {
      options->persist_config = true;
      options->persist_mode = 0;
    }
  else if (streq (p[0], "mktun"))
    {
      options->persist_config = true;
      options->persist_mode = 1;
    }
#endif
  else
    {
      if (file)
	msg (M_WARN|M_NOPREFIX, "Unrecognized option or missing parameter(s) in %s:%d: %s", file, line, p[0]);
      else
	msg (M_WARN|M_NOPREFIX, "Unrecognized option or missing parameter(s): --%s", p[0]);
      usage_small ();
    }
  return i;
}
