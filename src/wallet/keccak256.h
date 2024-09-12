#ifndef BITCOIN_WALLET_KECCAK_H
#define BITCOIN_WALLET_KECCAK_H

#include <cstdint>

int keccak256(const uint8_t *in, unsigned inlen, void *out32);

#endif // BITCOIN_WALLET_KECCAK_H

