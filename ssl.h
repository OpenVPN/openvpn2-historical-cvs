/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002 James Yonan <jim@yonan.net>
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

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include "basic.h"
#include "crypto.h"
#include "packet_id.h"
#include "session_id.h"
#include "reliable.h"
#include "socket.h"

/*
 * Openvpn Protocol.
 *
 * UDP Packet:
 *   packet opcode (high 5 bits, see P_ constants below)
 *   key_id (low 3 bits, see key_id in struct tls_session below for comment)
 *   payload (n bytes)
 *
 * P_CONTROL* and P_ACK Payload:
 *   session_id (random 64 bit value to identify session)
 *   hmac for authentication (usually 16 or 20 bytes)
 *   packet-id for replay protection (4 or 8 bytes, includes
 *     sequence number and optional time_t timestamp)
 *   acknowledge packet_id array length (1 byte)
 *   acknowledge packet-id array (if length > 0)
 *   acknowledge remote session_id (if length > 0)
 *   control packet-id (4 bytes)
 *   TLS ciphertext (n bytes) (only for P_CONTROL)
 *
 * TLS plaintext packet:
 *   cipher key length in bytes (1 byte)
 *   cipher key (n bytes)
 *   hmac key length in bytes (1 byte)
 *   hmac key (n bytes)
 *   options string (n bytes, null terminated, client/server options string must match)
 *
 * P_DATA Payload:
 *   hmac of ciphertext IV + ciphertext (if enabled by --auth)
 *   ciphertext IV (size is cipher-dependent, if not disabled by --no-iv)
 *   P_DATA ciphertext
 *
 * P_DATA plaintext
 *   packet_id (4 or 8 bytes, if not disabled by --no-replay)
 *   user plaintext (n bytes)
 *
 * Notes:
 *   (1) Acknowledgements can be encoded in either the dedicated P_ACK record
 *       or they can be prepended to a P_CONTROL* record.
 *   (2) P_DATA and P_CONTROL/P_ACK use independent packet-id sequences because
 *       P_DATA is an unreliable channel while P_CONTROL/P_ACK is a reliable channel.
 */

/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte */
#define P_KEY_ID_MASK                  0x07
#define P_OPCODE_SHIFT                 3

/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
#define P_CONTROL_HARD_RESET_CLIENT_V1 1     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V1 2     /* initial key from server, forget previous state */
#define P_CONTROL_SOFT_RESET_V1        3     /* new key, graceful transition from old to new key */
#define P_CONTROL_V1                   4     /* control channel packet (usually TLS ciphertext) */
#define P_ACK_V1                       5     /* acknowledgement for packets received */
#define P_DATA_V1                      6     /* data channel packet (uncompressed) */

/* define the range of legal opcodes */
#define P_FIRST_OPCODE                 1
#define P_LAST_OPCODE                  6

/* key negotiation states */
#define S_ERROR          -1
#define S_UNDEF           0
#define S_INITIAL         1	/* tls_init() was called */
#define S_PRE_START       2	/* waiting for initial reset & acknowledgement */
#define S_START           3	/* ready to exchange keys */
#define S_SENT_KEY        4	/* client does S_SENT_KEY -> S_GOT_KEY */
#define S_GOT_KEY         5	/* server does S_GOT_KEY -> S_SENT_KEY */
#define S_ACTIVE          6	/* ready to exchange data channel packets */

/*
 * Are we ready to receive data channel packets?
 *
 * Also, if true, we can safely assume session has been
 * authenticated by TLS.
 *
 * NOTE: Assumes S_SENT_KEY + 1 == S_GOT_KEY.
 */
#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))

/*
 * Hard reset received?
 */
#define HARD_RESET(op) \
  ((op) == P_CONTROL_HARD_RESET_CLIENT_V1 \
  || (op) == P_CONTROL_HARD_RESET_SERVER_V1)

/*
 * Max number of acknowledgments that
 * can "hitch a ride" on an outgoing
 * non-P_ACK_V1 control packet.
 */
#define CONTROL_SEND_ACK_MAX 4

/*
 * Represents a single instantiation of a TLS negotiation and
 * data channel key exchange.  4 keys are kept: encrypt hmac,
 * decrypt hmac, encrypt cipher, and decrypt cipher.  The TLS
 * control channel is used to exchange these keys.
 * Each hard or soft reset will build
 * a fresh key_state.  Normally an openvpn session will contain two
 * key_state objects, one for the current TLS connection, and other
 * for the retiring or "lame duck" key.  The lame duck key_state is
 * used to maintain transmission continuity on the data-channel while
 * a key renegotiation is taking place.
 */
struct key_state
{
  int state;
  int key_id;			/* inherited from struct tls_session below */

  SSL *ssl;			/* SSL object -- new obj created for each new key */
  BIO *ssl_bio;			/* read/write plaintext from here */
  BIO *ct_in;			/* write ciphertext to here */
  BIO *ct_out;			/* read ciphertext from here */

  time_t established;		/* when our state went S_ACTIVE */
  time_t must_negotiate;	/* key negotiation times out if not finished before this time */
  time_t must_die;		/* this object is destroyed at this time */

  int initial_opcode;		/* our initial P_ opcode */
  bool burst;			/* during hard reset used to control burst retransmit */
  struct session_id session_id_remote; /* peer's random session ID */
  struct sockaddr_in remote_addr;      /* peer's IP addr */
  struct packet_id packet_id;	       /* for data channel, to prevent replay attacks */

  struct key_ctx_bi key;	       /* data channel keys for encrypt/decrypt/hmac */

  struct buffer plaintext_read_buf;
  struct buffer plaintext_write_buf;
  struct buffer ack_write_buf;
  struct reliable send_reliable; /* holds a copy of outgoing packets until ACK received */
  struct reliable rec_reliable;	 /* order incoming ciphertext packets before we pass to TLS */
  struct reliable_ack rec_ack;	 /* buffers all packet IDs we want to ACK back to sender */

  int n_bytes;			 /* how many bytes sent/recvd since last key exchange */
  int n_packets;		 /* how many packets sent/recvd since last key exchange */
};

/*
 * Our const options, obtained directly or derived from
 * command line options.
 */
struct tls_options
{
  /* our master SSL_CTX from which all SSL objects derived */
  SSL_CTX *ssl_ctx;

  /* data channel cipher, hmac, and key lengths */
  struct key_type key_type;

  /* true if we are a TLS server, client otherwise */
  bool server;

  /* an options string that must match between client and server */
  char *options;

  /* from command line */
  bool packet_id;
  int transition_window;
  int handshake_window;
  int packet_timeout;
  int renegotiate_bytes;
  int renegotiate_packets;
  int renegotiate_seconds;

  /* use 32 bit or 64 bit packet-id? */
  bool packet_id_long_form;

  /* packet authentication for TLS handshake */
  struct crypto_options tls_auth;
  struct key_ctx_bi tls_auth_key;

  /* frame parameters for TLS control channel */
  struct frame frame;
};

/* index into tls_session.key */
#define KS_PRIMARY    0		/* the primary key */
#define KS_LAME_DUCK  1		/* the key that's going to retire soon */
#define KS_SIZE       2

/*
 * A tls_session lives through multiple key_state life-cycles.  Soft resets
 * will reuse a tls_session object, but hard resets or errors will require
 * that a fresh object be built.  Normally three tls_session objects are maintained
 * by an active openvpn session.  The first is the current, TLS authenticated
 * session, the second is used to process connection requests from a new
 * client that would usurp the current session if successfully authenticated,
 * and the third is used as a repository for a "lame-duck" key in the event
 * that the primary session resets due to error while the lame-duck key still
 * has time left before its expiration.  Lame duck keys are used to maintain
 * the continuity of the data channel connection while a new key is being
 * negotiated.
 */
struct tls_session
{
  /* const options and config info */
  const struct tls_options *opt;

  /* authenticate control packets */
  struct crypto_options tls_auth;
  struct packet_id tls_auth_pid;

  int initial_opcode;		/* our initial P_ opcode */
  struct session_id session_id;	/* our random session ID */
  int key_id;			/* increments with each soft reset (for key renegotiation) */

  int limit_next;               /* used for traffic shaping on the control channel */

  struct key_state key[KS_SIZE];
};

/* index into tls_multi.session */
#define TM_ACTIVE    0
#define TM_UNTRUSTED 1
#define TM_LAME_DUCK 2
#define TM_SIZE      3

/*
 * The number of keys we will scan on encrypt or decrypt.  The first
 * is the "active" key.  The second is the lame_duck or retiring key
 * associated with the active key's session ID.  The third is a detached
 * lame duck session that only occurs in situations where a key renegotiate
 * failed on the active key, but a lame duck key was still valid.  By
 * preserving the lame duck session, we can be assured of having a data
 * channel key available even when network conditions are so bad that
 * we can't negotiate a new key within the time allotted.
 */
#define KEY_SCAN_SIZE 3

/*
 * An openvpn session running with TLS enabled has one tls_multi object.
 */
struct tls_multi
{
  /* const options and config info */
  struct tls_options opt;

  /*
   * A list of key_state objects in the order they should be
   * scanned by data channel encrypt and decrypt routines.
   */
  struct key_state* key_scan[KEY_SCAN_SIZE];

  /*
   * used by tls_pre_encrypt to communicate the encrypt key
   * to tls_post_encrypt()
   */
  struct key_state *save_ks;	/* temporary pointer used between pre/post routines */

  struct tls_session session[TM_SIZE];
};

void init_ssl_lib ();
void free_ssl_lib ();

/* Build master SSL_CTX object that serves for the whole of openvpn instantiation */
SSL_CTX *init_ssl (bool server,
		   const char *ca_file,
		   const char *dh_file,
		   const char *cert_file,
		   const char *priv_key_file, const char *cipher_list);

struct tls_multi *tls_multi_init (struct tls_options *tls_options,
				  struct udp_socket *udp_socket);

void tls_multi_init_finalize(struct tls_multi* multi, const struct frame* frame);

bool tls_multi_process (struct tls_multi *multi,
			struct buffer *to_udp,
			struct sockaddr_in *to_udp_addr,
			struct udp_socket *to_udp_socket,
			time_t * wakeup,
			const time_t current);

void tls_multi_free (struct tls_multi *multi, bool clear);

bool tls_pre_decrypt (struct tls_multi *multi,
		      struct sockaddr_in *from,
		      struct buffer *buf,
		      struct crypto_options *opt,
		      const time_t current);

void tls_pre_encrypt (struct tls_multi *multi,
		      struct buffer *buf, struct crypto_options *opt);

void tls_post_encrypt (struct tls_multi *multi, struct buffer *buf);

void show_available_tls_ciphers ();
void get_highest_preference_tls_cipher (char *buf, int size);

int pem_password_callback (char *buf, int size, int rwflag, void *u);

void tls_set_verify_command (const char *cmd);

void tls_adjust_frame_parameters(struct frame *frame);

/*
 * protocol_dump() flags
 */
#define PD_TLS_AUTH_HMAC_SIZE_MASK 0xFF
#define PD_SHOW_DATA               (1<<8)
#define PD_TLS                     (1<<9)

const char *protocol_dump (struct buffer *buffer, unsigned int flags);

#endif /* USE_CRYPTO && USE_SSL */
