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

/*
 * 2004-01-28: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include "basic.h"
#include "mtu.h"
#include "route.h"
#include "tun.h"

/*
 * Maximum number of parameters associated with an option,
 * including the option name itself.
 */
#define MAX_PARMS 5

extern const char title_string[];

#if P2MP
/* parameters to be pushed to peer */

#define MAX_PUSH_LIST_LEN 1024 /* This parm is related to PLAINTEXT_BUFFER_SIZE in ssl.h */

struct push_list {
  /* newline delimited options, like config file */
  char options[MAX_PUSH_LIST_LEN];
};

/* internal OpenVPN route */
struct iroute {
  in_addr_t start;
  in_addr_t end;
  struct iroute *next;
};

#endif

/* Command line options */
struct options
{
  struct gc_arena gc;

  /* first config file */
  const char *config;

  /* major mode */
# define MODE_POINT_TO_POINT 0
# define MODE_SERVER         1
  int mode;

  /* persist parms */
  bool persist_config;
  int persist_mode;

#ifdef USE_CRYPTO
  bool askpass;
  bool show_ciphers;
  bool show_digests;
#ifdef USE_SSL
  bool show_tls_ciphers;
#endif
  bool genkey;
#endif

  /* Networking parms */
  const char *local;
  const char *remote;
  int local_port;
  int remote_port;
  bool remote_float;
  const char *ipchange;
  bool bind_local;
  const char *dev;
  const char *dev_type;
  const char *dev_node;
  const char *ifconfig_local;
  const char *ifconfig_remote_netmask;
  bool ifconfig_noexec;
  bool ifconfig_nowarn;
#ifdef HAVE_GETTIMEOFDAY
  int shaper;
#endif
  int tun_mtu;           /* MTU of tun device */
  int tun_mtu_extra;
  bool tun_mtu_extra_defined;
  int link_mtu;          /* MTU of device over which tunnel packets pass via TCP/UDP */
  bool tun_mtu_defined;  /* true if user overriding parm with command line option */
  bool link_mtu_defined; /* true if user overriding parm with command line option */

  /* Protocol type (PROTO_UDP or PROTO_TCP) */
  int proto;
  int connect_retry_seconds;
  bool connect_retry_defined;

  /* Advanced MTU negotiation and datagram fragmentation options */
  int mtu_discover_type; /* used if OS supports setting Path MTU discovery options on socket */
  bool mtu_test;

  int fragment;          /* internal fragmentation size */

  bool mlock;
  int inactivity_timeout;
  int ping_send_timeout;        /* Send a TCP/UDP ping to remote every n seconds */
  int ping_rec_timeout;         /* Expect a TCP/UDP ping from remote at least once every n seconds */
  bool ping_timer_remote;       /* Run ping timer only if we have a remote address */
  bool tun_ipv6;                /* Build tun dev that supports IPv6 */

# define PING_UNDEF   0
# define PING_EXIT    1
# define PING_RESTART 2
  int ping_rec_timeout_action;  /* What action to take on ping_rec_timeout (exit or restart)? */

  bool persist_tun;             /* Don't close/reopen TUN/TAP dev on SIGUSR1 or PING_RESTART */
  bool persist_local_ip;        /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
  bool persist_remote_ip;       /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */
  bool persist_key;             /* Don't re-read key files on SIGUSR1 or PING_RESTART */

  int mssfix;                   /* Upper bound on TCP MSS */

#if PASSTOS_CAPABILITY
  bool passtos;                  
#endif

  int resolve_retry_seconds;    /* If hostname resolve fails, retry for n seconds */

  struct tuntap_options tuntap_options;

  /* Misc parms */
  const char *username;
  const char *groupname;
  const char *chroot_dir;
  const char *cd_dir;
  const char *writepid;
  const char *up_script;
  const char *down_script;
  bool up_delay;
  bool up_restart;
  bool daemon;

  /* inetd modes defined in socket.h */
  int inetd;

  bool log;
  int nice;
  int verbosity;
  int mute;
  bool gremlin;

#ifdef USE_LZO
  bool comp_lzo;
  bool comp_lzo_adaptive;
#endif

  /* route management */
  const char *route_script;
  const char *route_default_gateway;
  bool route_noexec;
  int route_delay;
  bool route_delay_defined;
  struct route_option_list *routes;

  /* http proxy */
  const char *http_proxy_server;
  int http_proxy_port;
  const char *http_proxy_auth_method;
  const char *http_proxy_auth_file;
  bool http_proxy_retry;

  /* socks proxy */
  const char *socks_proxy_server;
  int socks_proxy_port;
  bool socks_proxy_retry;

  /* Enable options consistency check between peers */
  bool occ;

#ifdef USE_PTHREAD
  int n_threads;
  int nice_work;
#endif

#if P2MP
  struct push_list *push_list;
  bool pull; /* client pull of config options from server */
  bool ifconfig_pool_defined;
  in_addr_t ifconfig_pool_start;
  in_addr_t ifconfig_pool_end;
  int real_hash_size;
  int virtual_hash_size;
  const char *client_connect_script;
  const char *client_disconnect_script;
  const char *tmp_dir;
  const char *client_config_dir;
  int bcast_delay;
  struct iroute *iroutes;
  bool push_ifconfig_defined;
  in_addr_t push_ifconfig_local;
  in_addr_t push_ifconfig_remote_netmask;
  bool enable_c2c;
#endif

#ifdef USE_CRYPTO
  /* Cipher parms */
  const char *shared_secret_file;
  int key_direction;
  bool ciphername_defined;
  const char *ciphername;
  bool authname_defined;
  const char *authname;
  int keysize;
  bool replay;
  int replay_window;
  int replay_time;
  const char *packet_id_file;
  bool use_iv;
  bool test_crypto;

#ifdef USE_SSL
  /* TLS (control channel) parms */
  bool tls_server;
  bool tls_client;
  const char *ca_file;
  const char *dh_file;
  const char *cert_file;
  const char *priv_key_file;
  const char *cipher_list;
  const char *tls_verify;
  const char *tls_remote;
  const char *crl_file;

  /* data channel key exchange method */
  int key_method;

  /* Per-packet timeout on control channel */
  int tls_timeout;

  /* Data channel key renegotiation parameters */
  int renegotiate_bytes;
  int renegotiate_packets;
  int renegotiate_seconds;

  /* Data channel key handshake must finalize
     within n seconds of handshake initiation. */
  int handshake_window;

  /* Old key allowed to live n seconds after new key goes active */
  int transition_window;

  /* Special authentication MAC for TLS control channel */
  const char *tls_auth_file;		/* shared secret */

  /* Allow only one session */
  bool single_session;
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
};

#define streq(x, y) (!strcmp((x), (y)))

/*
 * Option classes.
 */
#define OPT_P_GENERAL   (1<<0)
#define OPT_P_UP        (1<<1)
#define OPT_P_ROUTE     (1<<2)
#define OPT_P_IPWIN32   (1<<3)
#define OPT_P_SCRIPT    (1<<4)
#define OPT_P_SETENV    (1<<5)
#define OPT_P_SHAPER    (1<<6)
#define OPT_P_TIMER     (1<<7)
#define OPT_P_PERSIST   (1<<8)
#define OPT_P_COMP      (1<<9)  /* TODO */
#define OPT_P_MESSAGES  (1<<10)
#define OPT_P_CRYPTO    (1<<11) /* TODO */
#define OPT_P_TLS_PARMS (1<<12) /* TODO */
#define OPT_P_MTU       (1<<13) /* TODO */
#define OPT_P_NICE      (1<<14)
#define OPT_P_PUSH      (1<<15)
#define OPT_P_INSTANCE  (1<<16)
#define OPT_P_CONFIG    (1<<17)

#define OPT_P_DEFAULT   (~OPT_P_INSTANCE)

#if P2MP
#define PULL_DEFINED(opt) ((opt)->pull)
#else
#define PULL_DEFINED(opt) (false)
#endif

void parse_argv (struct options* options,
		 int argc,
		 char *argv[],
		 int msglevel,
		 unsigned int permission_mask,
		 unsigned int *option_types_found);

void notnull (const char *arg, const char *description);

void usage_small (void);

void init_options (struct options *o);
void uninit_options (struct options *o);

void setenv_settings (const struct options *o);
void show_settings (const struct options *o);

bool string_defined_equal (const char *s1, const char *s2);

const char *options_string_version (const char* s, struct gc_arena *gc);

char *options_string (const struct options *o,
		      const struct frame *frame,
		      const struct tuntap *tt,
		      bool remote,
		      struct gc_arena *gc);

int options_cmp_equal (char *actual, const char *expected, size_t actual_n);

void options_warning (char *actual, const char *expected, size_t actual_n);

void options_postprocess (struct options *options, bool first_time);

bool apply_push_options (struct options *options,
			 struct buffer *buf,
			 unsigned int permission_mask,
			 unsigned int *option_types_found);

bool is_persist_option (const struct options *o);

void options_detach (struct options *o);

void options_server_import (struct options *o,
			    const char *filename,
			    int msglevel,
			    unsigned int permission_mask,
			    unsigned int *option_types_found);

#endif
