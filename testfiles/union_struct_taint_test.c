/*
 * union_struct_taint_test.c
 *
 * Tests that the rule engine correctly propagates taint across union members
 * (since union members share the same memory address) while keeping struct
 * field writes isolated (struct fields are independent memory locations).
 *
 * Pattern: writing tainted data to union.member_a should taint union.member_b;
 *           writing tainted data to struct.field_a must NOT taint struct.field_b.
 *
 * Functions use vuln_ or safe_ prefixes for the finding-matrix runner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* =================== Type definitions =================== */

union NumericOverlay {
    int   i;
    float f;
    char  c;
};

union NetworkPacket {
    int   length;
    char  raw[4];
};

struct StrictFields {
    int  a;
    char b;
    int  c;
};

/* =================== Vulnerable: union member taint propagation =================== */

/*
 * VULNERABLE: attacker writes a char to union.c; the same memory is then
 * read as union.i and used as a divisor.  After union taint propagation the
 * divisor is tainted → CWE369-TAINTED-DIVISOR must fire.
 */
int vuln_union_char_to_int_divisor(int fd) {
    union NumericOverlay u;
    char buf[4];
    read(fd, buf, sizeof(buf));
    u.c = buf[0];           /* taint flows into union char member   */
    return 100 / u.i;       /* union.i shares memory with union.c   */
}

/*
 * VULNERABLE: raw network bytes written into union.raw; union.length
 * (same memory) is used in an allocation without bounds check → CWE770 / CWE125.
 */
void *vuln_union_raw_to_length(int fd) {
    union NetworkPacket pkt;
    recv(fd, pkt.raw, sizeof(pkt.raw), 0);  /* taint via raw member  */
    /* pkt.length shares memory with pkt.raw — tainted by union propagation */
    char *buf = malloc(pkt.length);         /* unbounded alloc from tainted size */
    return buf;
}

/*
 * VULNERABLE: two-step union confusion — attacker controls float value which
 * reinterprets as int for arithmetic, used in index into another buffer.
 */
char vuln_union_float_to_index(int fd) {
    union NumericOverlay u;
    float tmp;
    recv(fd, (char *)&tmp, sizeof(tmp), 0);
    u.f = tmp;                              /* taint flows to union.f  */
    char arr[256] = {0};
    return arr[u.i & 0xFF];                 /* union.i is tainted → OOB risk */
}

/* =================== Safe: struct fields are independent =================== */

/*
 * SAFE: struct fields have independent memory addresses.
 * Writing tainted data to s.b must NOT propagate to s.a.
 * Dividing by s.a should produce no CWE369 finding.
 */
int safe_struct_field_isolation(int fd) {
    struct StrictFields s;
    char buf[4];
    s.a = 5;                /* s.a is a literal 5, not tainted */
    read(fd, buf, sizeof(buf));
    s.b = buf[0];           /* only s.b receives tainted data  */
    return 100 / s.a;       /* s.a is clean — must not fire    */
}

/*
 * SAFE: struct with tainted write to one field; another field is written
 * separately from a safe literal and used as divisor.
 */
int safe_struct_two_fields(int fd) {
    struct StrictFields s;
    char buf[16];
    read(fd, buf, sizeof(buf));
    s.b = buf[0];           /* tainted */
    s.a = 10;               /* safe literal */
    s.c = 2;                /* safe literal */
    return s.a / s.c;       /* both fields are literal-assigned — clean */
}

/*
 * SAFE: union member written from literal (not tainted), then divided.
 * No taint in system → nothing should fire.
 */
int safe_union_literal_divisor(void) {
    union NumericOverlay u;
    u.c = 'A';              /* literal, not tainted */
    return 100 / u.i;       /* u.i is type-confused from 'A'=65, but no taint */
}
