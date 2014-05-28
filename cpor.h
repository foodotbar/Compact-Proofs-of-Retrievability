
#ifndef CPOR_H_
#define CPOR_H_

//#define DEBUG

#if defined(DEBUG)
#define DEBUG_PRINT(...) \
    printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

/* The security parameter lambda, in bits. */
#define CPOR_LAMBDA     80
/* Size of the large prime number.
 * Shall be twice as large as lambda. */
#define CPOR_PRIME_BITS     (CPOR_LAMBDA * 2)
#define CPOR_PRIME_BYTES    (CPOR_PRIME_BITS / 8)
/* Elements of Zp (including the alpha series in the private key,
 * and the per-block tag) are of variable length, when writing to file,
 * this is not so convenient.
 * Therefore, each element is aligned to its maximum length (20 bytes now),
 * and accompanied by an int indicating its length. */
#define CPOR_PRIME_ELEM_BYTES   CPOR_PRIME_BYTES
/* Size in bytes of the encryption key. Currently AES-128 is used. */
#define CPOR_ENC_KEY_BYTES  (128 / 8)
/* Size in bytes of the MAC key. Currently HMAC-SHA1 is used as MAC.
 * Although the key for HMAC can be of any length,
 * it's recommended to use keys with at least the same length
 * as that of the unerlying hash output, e.g., 20 bytes of SHA-1.
 */
#define CPOR_MAC_KEY_BYTES   (160 / 8)
/* Output size of HAMC, which is the output size of the underlying hash (currently SHA1). */
#define CPOR_MAC_OUTPUT_BYTES   (160 / 8)
/* Size in bytes of the PRF key. Currently HMAC-SHA1 is used as PRF. */
#define CPOR_PRF_KEY_BYTES   (160 / 8)

/* File names/suffices. */
#define CPOR_MASTER_KEYS_FILE       "master_keys"
#define CPOR_META_FILE_SUFFIX       ".metadata"
#define CPOR_TAG_FILE_SUFFIX        ".tag"
#define CPOR_CHALLENGE_FILE_SUFFIX  ".challenge"
#define CPOR_RESPONSE_FILE_SUFFIX    ".response"

/* Block size. */
#define CPOR_BLOCK_SIZE     4096
/* XXX In this implementation, we made an assumption 
 * that the file size is multiple of CPOR_BLOCK_ZIE. */
/* Sector size in bytes.
 * The content of a sector is required to be an element in Zp.
 * It's sufficient to make sector size smaller than that of the prime number,
 * because any k < p is an element of Zp.
 * Although one bit less (79 bits) will be OK, we choose a sector size of
 * 8 bytes s.t. CPOR_BLOCK_SIZE is multiple of CPOR_SECTOR_SIZE. */
#define CPOR_SECTOR_SIZE    8
/* How many sectors in one block. That's the variable 's' in the paper. */
#define CPOR_S  (CPOR_BLOCK_SIZE / CPOR_SECTOR_SIZE)

#endif // CPOR_H_

