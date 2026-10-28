/* Offline compatibility probe for Dovecot 2.1.17's dispatch semantics.
 * Independently implemented from the official release's read_dh_parameters_next
 * and ssl_tmp_dh_callback; no Dovecot or OpenSSL global setting is changed.
 * It uses OpenSSL's real d2i_DHparams and checks the selected object's prime.
 */
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int actual_bits(DH *dh) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    const BIGNUM *prime;
    DH_get0_pqg(dh, &prime, NULL, NULL);
    return BN_num_bits(prime);
#else
    return BN_num_bits(dh->p);
#endif
}

int main(int argc, char **argv) {
    unsigned char bytes[1025];
    const unsigned char *cursor;
    size_t size, offset = 0;
    int selector, length, count = 0, bits, check = 0;
    DH *dh512 = NULL, *dh1024 = NULL, *value;
    FILE *file;
    if (argc != 2 || sizeof(int) != 4 || (file = fopen(argv[1], "rb")) == NULL) return 2;
    size = fread(bytes, 1, sizeof(bytes), file); fclose(file);
    if (size == 0 || size > 1024) return 3;
    while (1) {
        if (offset + 4 > size) return 4;
        memcpy(&selector, bytes + offset, 4); offset += 4;
        if (selector == 0) break;
        if (selector != 512 && selector != 1024) return 5;
        if (offset + 4 > size) return 6;
        memcpy(&length, bytes + offset, 4); offset += 4;
        if (length <= 0 || offset + (size_t)length > size) return 7;
        cursor = bytes + offset;
        value = d2i_DHparams(NULL, &cursor, length);
        if (value == NULL || cursor != bytes + offset + length) return 8;
        if (selector == 512) { if (dh512) return 9; dh512 = value; }
        else { if (dh1024) return 10; dh1024 = value; }
        offset += length; count++;
    }
    if (offset != size || count != 2 || dh512 == NULL || dh1024 == NULL) return 11;
    /* The native non-export callback returns this exact object irrespective
       of OpenSSL's nominal requested keylength. */
    bits = actual_bits(dh1024);
    if (bits != 3072 || actual_bits(dh512) != 3072) return 12;
    if (DH_check(dh1024, &check) != 1 || check != 0) return 13;
    printf("legacy_selector_512_actual_bits=%d\n", actual_bits(dh512));
    printf("non_export_selector_1024_actual_bits=%d\n", bits);
    DH_free(dh512); DH_free(dh1024);
    return 0;
}
