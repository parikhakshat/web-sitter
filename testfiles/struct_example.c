/*
 * Example C file with structs for testing struct-aware rule matching.
 *
 * Intended to exercise:
 * - Struct type extraction (net_dev with addr_len, name)
 * - Variable-to-type (dev -> struct net_dev *)
 * - field_expression: dev->addr_len, dev->name (should be treated as struct-derived)
 * - memcpy with struct field size (should NOT be flagged as overflow)
 * - sprintf without bound (should be flagged)
 * - Optional: downcast only when from void* (not from field_expression)
 */

#include <string.h>
#include <stdio.h>

struct net_dev {
	unsigned short addr_len;
	char name[16];
	int flags;
};

struct net_dev *get_dev(void);

void safe_copy(struct net_dev *dev, char *dest)
{
	/* Struct-derived size: dev->addr_len - should be suppressed by struct model */
	memcpy(dest, dev->name, dev->addr_len);
}

void unsafe_sprintf_example(struct net_dev *dev)
{
	char buf[32];
	/* Valid finding: sprintf has no size limit */
	sprintf(buf, "device %s", dev->name);
}

void another_safe_memcpy(struct net_dev *dev, unsigned char *out)
{
	/* Size from struct field - should be suppressed */
	memcpy(out, get_dev()->name, dev->addr_len);
}

void zero_size_memcpy(struct net_dev *dev)
{
	char buf[8];
	/* Would be CWE628-ZERO-SIZE if size were 0; here size is struct field */
	memcpy(buf, dev->name, dev->addr_len);
}

int main(void)
{
	struct net_dev my_dev = {
		.addr_len = 6,
		.name = "eth0",
		.flags = 0
	};
	char buffer[32];

	safe_copy(&my_dev, buffer);
	unsafe_sprintf_example(&my_dev);
	another_safe_memcpy(&my_dev, (unsigned char *)buffer);

	return 0;
}
