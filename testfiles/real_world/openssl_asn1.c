/*
 * Simplified OpenSSL-style ASN.1 parser snippet.
 * Demonstrates CWE-190 (Integer Overflow) when computing buffer sizes
 * from attacker-controlled length fields in DER-encoded data.
 *
 * In real ASN.1 parsing, a multi-byte length field is read from an
 * untrusted certificate/message.  If the parser multiplies or adds
 * length values without overflow checks, an attacker can craft a
 * maliciously large length that wraps to a small value, causing a
 * subsequent heap buffer overflow on write.
 *
 * References: CVE-2022-0778, CVE-2021-3449 (similar integer mishandling)
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Minimal ASN.1 type tags                                             */
/* ------------------------------------------------------------------ */
#define ASN1_TAG_INTEGER    0x02
#define ASN1_TAG_BITSTRING  0x03
#define ASN1_TAG_OCTETSTRING 0x04
#define ASN1_TAG_SEQUENCE   0x30

/* ------------------------------------------------------------------ */
/* Internal structures                                                 */
/* ------------------------------------------------------------------ */

typedef struct asn1_string {
    unsigned char *data;
    int            length;
    int            type;
    int            flags;
} ASN1_STRING;

typedef struct asn1_item {
    int            tag;
    ASN1_STRING   *value;
    struct asn1_item *next;
} ASN1_ITEM;

/* ------------------------------------------------------------------ */
/* Low-level DER length decoder                                        */
/* ------------------------------------------------------------------ */

/*
 * asn1_get_length:
 *   Reads a BER/DER length from `p`.  For the long form (first byte
 *   has high bit set) the subsequent bytes encode the length.
 *
 *   Returns decoded length, or -1 on error.
 *   Advances *p past the length bytes; *max is decremented accordingly.
 */
static long asn1_get_length(const unsigned char **p, long *max) {
    long length;
    const unsigned char *q = *p;

    if (*max <= 0)
        return -1;

    if (*q & 0x80) {                /* long form */
        int num_bytes = *q & 0x7f;
        if (num_bytes == 0 || num_bytes > 4 || num_bytes >= *max)
            return -1;
        q++;
        (*max)--;
        length = 0;
        while (num_bytes--) {
            /* Shift and accumulate — no overflow check on `length` */
            length = (length << 8) | *q++;
            (*max)--;
        }
    } else {
        length = *q++;              /* short form */
        (*max)--;
    }

    *p = q;
    return length;
}

/* ------------------------------------------------------------------ */
/* String value allocation                                             */
/* ------------------------------------------------------------------ */

/*
 * asn1_string_alloc:
 *   Allocates an ASN1_STRING with `len` bytes of storage.
 *
 *   VULNERABILITY (CWE-190): `header_len` is computed from
 *   attacker-controlled ASN.1 length fields.  The addition
 *   `len + header_len` can wrap around on 32-bit systems or when
 *   both values approach SIZE_MAX, resulting in a tiny allocation that
 *   is subsequently written beyond its end.
 */
static ASN1_STRING *asn1_string_alloc(int len, int header_len, int type) {
    ASN1_STRING *ret;

    ret = (ASN1_STRING *)malloc(sizeof(ASN1_STRING));
    if (!ret)
        return NULL;

    /* INTEGER OVERFLOW: len + header_len wraps if len is close to INT_MAX */
    int total = len + header_len;   /* CWE-190 — no overflow check */

    ret->data = (unsigned char *)malloc(total + 1);   /* heap alloc with wrapped size */
    if (!ret->data) {
        free(ret);
        return NULL;
    }

    ret->length = len;   /* real length — larger than allocated `total` */
    ret->type   = type;
    ret->flags  = 0;
    return ret;
}

/* ------------------------------------------------------------------ */
/* Sequence / constructed type parser                                  */
/* ------------------------------------------------------------------ */

/*
 * asn1_parse_sequence:
 *   Parses a SEQUENCE element from a DER buffer.
 *   Recursively processes child elements up to `max_depth` levels.
 *
 *   The `plen` parameter comes directly from `asn1_get_length()` which
 *   reads from attacker-supplied data — no upper bound is enforced
 *   before the multiplication below.
 */
static ASN1_ITEM *asn1_parse_sequence(const unsigned char *p,
                                       long plen,
                                       int depth,
                                       int max_depth) {
    if (depth > max_depth || plen <= 0)
        return NULL;

    ASN1_ITEM *head = NULL, *tail = NULL;
    const unsigned char *end = p + plen;

    while (p < end) {
        int tag = *p++;
        long remain = end - p;

        long len = asn1_get_length(&p, &remain);
        if (len < 0 || len > remain)
            break;

        ASN1_ITEM *item = (ASN1_ITEM *)malloc(sizeof(ASN1_ITEM));
        if (!item)
            break;

        item->tag  = tag;
        item->next = NULL;

        if (tag == ASN1_TAG_SEQUENCE) {
            item->value = NULL;
            item->next  = asn1_parse_sequence(p, len, depth + 1, max_depth);
        } else {
            /*
             * VULNERABILITY path: `len` is attacker-controlled; passing it as
             * `header_len` argument causes the overflow inside asn1_string_alloc.
             * In a real parser, `header_len` would include tag+length overhead
             * computed from the same untrusted stream.
             */
            int header_overhead = (int)len * 2;   /* integer overflow if len > INT_MAX/2 */
            item->value = asn1_string_alloc((int)len, header_overhead, tag);
            if (item->value && item->value->data && len > 0) {
                memcpy(item->value->data, p, len);   /* writes `len` bytes into undersized buffer */
            }
        }

        p += len;

        if (!head) {
            head = tail = item;
        } else {
            tail->next = item;
            tail = item;
        }
    }

    return head;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

/*
 * asn1_parse_der:
 *   Top-level parser for a DER-encoded buffer.
 *   `buf` and `buf_len` come from the network / certificate file —
 *   they are fully attacker-controlled.
 */
ASN1_ITEM *asn1_parse_der(const unsigned char *buf, size_t buf_len) {
    if (!buf || buf_len < 2)
        return NULL;

    const unsigned char *p = buf;
    long remain = (long)buf_len;

    int tag = *p++;
    remain--;

    long len = asn1_get_length(&p, &remain);
    if (len < 0 || len > remain)
        return NULL;

    if (tag == ASN1_TAG_SEQUENCE)
        return asn1_parse_sequence(p, len, 0, 16);

    /* Single primitive element */
    ASN1_ITEM *item = (ASN1_ITEM *)malloc(sizeof(ASN1_ITEM));
    if (!item)
        return NULL;
    item->tag  = tag;
    item->next = NULL;
    item->value = asn1_string_alloc((int)len, 4, tag);
    if (item->value && item->value->data && len > 0)
        memcpy(item->value->data, p, len);
    return item;
}

/* ------------------------------------------------------------------ */
/* Cleanup                                                             */
/* ------------------------------------------------------------------ */

static void asn1_item_free(ASN1_ITEM *item) {
    while (item) {
        ASN1_ITEM *next = item->next;
        if (item->value) {
            free(item->value->data);
            free(item->value);
        }
        free(item);
        item = next;
    }
}

/* ------------------------------------------------------------------ */
/* Test harness                                                        */
/* ------------------------------------------------------------------ */

int main(void) {
    /*
     * Simulate reading a DER-encoded blob from stdin (attacker-controlled).
     * In production, this would come from a TLS ClientHello or certificate.
     */
    unsigned char der_buf[8192];
    size_t n = fread(der_buf, 1, sizeof(der_buf), stdin);
    if (n == 0) {
        /* Provide a minimal benign SEQUENCE for demonstration */
        der_buf[0] = ASN1_TAG_SEQUENCE;
        der_buf[1] = 3;
        der_buf[2] = ASN1_TAG_INTEGER;
        der_buf[3] = 1;
        der_buf[4] = 42;
        n = 5;
    }

    ASN1_ITEM *tree = asn1_parse_der(der_buf, n);
    if (!tree) {
        fprintf(stderr, "Parse failed\n");
        return 1;
    }

    printf("Parsed ASN.1 tree: root tag=0x%02x\n", tree->tag);
    asn1_item_free(tree);
    return 0;
}
