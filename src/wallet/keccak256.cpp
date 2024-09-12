
#include <wallet/keccak256.h>
#include <cstring>


// keccak256
// https://github.com/brainhub/SHA3IUF
#define SHA3_KECCAK_SPONGE_WORDS (((1600)/8)/sizeof(uint64_t))
#define SHA3_USE_KECCAK_FLAG 0x80000000
#define SHA3_CW(x) ((x) & (~SHA3_USE_KECCAK_FLAG))
#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#define SHA3_CONST(x) x##L
typedef struct sha3_context_ {
    uint64_t saved;
    union {
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    } u;
    unsigned byteIndex;
    unsigned wordIndex;
    unsigned capacityWords;
} sha3_context;
static const uint64_t keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};
static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};
static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};
static void keccakf(uint64_t s[25])
{
    int i, j, round;
    uint64_t t, bc[5];
#define KECCAK_ROUNDS 24
    for(round = 0; round < KECCAK_ROUNDS; round++) {
        for(i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        for(i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
            for(j = 0; j < 25; j += 5)
                s[j + i] ^= t;
        }
        t = s[1];
        for(i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = s[j];
            s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }
        for(j = 0; j < 25; j += 5) {
            for(i = 0; i < 5; i++)
                bc[i] = s[j + i];
            for(i = 0; i < 5; i++)
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        s[0] ^= keccakf_rndc[round];
    }
}
int sha3_Init(void *priv, unsigned bitSize) {
    sha3_context *ctx = (sha3_context *) priv;
    if( bitSize != 256 && bitSize != 384 && bitSize != 512 )
        return 1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->capacityWords = 2 * bitSize / (8 * sizeof(uint64_t));
    ctx->capacityWords |= SHA3_USE_KECCAK_FLAG;
    return 0;
}
void sha3_Update(void *priv, const uint8_t *buf, size_t len)
{
    sha3_context *ctx = (sha3_context *) priv;
    unsigned old_tail = (8 - ctx->byteIndex) & 7;
    size_t words;
    unsigned tail;
    size_t i;
    if(len < old_tail) {
        while (len--)
            ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
        return;
    }
    if(old_tail) {
        len -= old_tail;
        while (old_tail--)
            ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
        ctx->u.s[ctx->wordIndex] ^= ctx->saved;
        ctx->byteIndex = 0;
        ctx->saved = 0;
        if(++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
            keccakf(ctx->u.s);
            ctx->wordIndex = 0;
        }
    }
    words = len / sizeof(uint64_t);
    tail = len - words * sizeof(uint64_t);
    for(i = 0; i < words; i++, buf += sizeof(uint64_t)) {
        const uint64_t t = (uint64_t) (buf[0]) |
                ((uint64_t) (buf[1]) << 8 * 1) |
                ((uint64_t) (buf[2]) << 8 * 2) |
                ((uint64_t) (buf[3]) << 8 * 3) |
                ((uint64_t) (buf[4]) << 8 * 4) |
                ((uint64_t) (buf[5]) << 8 * 5) |
                ((uint64_t) (buf[6]) << 8 * 6) |
                ((uint64_t) (buf[7]) << 8 * 7);
        ctx->u.s[ctx->wordIndex] ^= t;
        if(++ctx->wordIndex ==
                (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
            keccakf(ctx->u.s);
            ctx->wordIndex = 0;
        }
    }
    while (tail--) {
        ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
}
void const *sha3_Finalize(void *priv)
{
    sha3_context *ctx = (sha3_context *) priv;
    uint64_t t;
    t = (uint64_t)(((uint64_t) 1) << (ctx->byteIndex * 8));
    ctx->u.s[ctx->wordIndex] ^= ctx->saved ^ t;
    ctx->u.s[SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords) - 1] ^= SHA3_CONST(0x8000000000000000UL);
    keccakf(ctx->u.s);
    {
        unsigned i;
        for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
            const unsigned t1 = (uint32_t) ctx->u.s[i];
            const unsigned t2 = (uint32_t) ((ctx->u.s[i] >> 16) >> 16);
            ctx->u.sb[i * 8 + 0] = (uint8_t) (t1);
            ctx->u.sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
            ctx->u.sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
            ctx->u.sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
            ctx->u.sb[i * 8 + 4] = (uint8_t) (t2);
            ctx->u.sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
            ctx->u.sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
            ctx->u.sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
        }
    }
    return (ctx->u.sb);
}
int keccak256(const uint8_t *in, unsigned inlen, void *out32) {
    int err;
    sha3_context c;
    err = sha3_Init(&c, 256);
    if( err != 0 )
        return err;
    sha3_Update(&c, in, inlen);
    const void *h = sha3_Finalize(&c);
    memcpy(out32, h, 32);
    return 0;
}

