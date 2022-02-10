#include "serializer.h"

void i2a(uint8_t* a, uint32_t asize, uint32_t offset, int i, uint32_t isize)
{
    uint32_t j;

    for (j = 0; j < isize && asize >= (offset + isize); j++) {
        a[offset + j] = (uint8_t)((i >> (j * 8)) & 0xff);
    }
}
