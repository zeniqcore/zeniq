// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <dma.h>

std::string COutPoint::ToString() const {
    return strprintf("COutPoint(%s, %u)", txid.ToString().substr(0, 10), n);
}

std::string CTxIn::ToString() const {
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull()) {
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    } else {
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    }
    if (nSequence != SEQUENCE_FINAL) {
        str += strprintf(", nSequence=%u", nSequence);
    }
    str += ")";
    return str;
}

std::string CTxOut::ToString() const {
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN,
                     (nValue % COIN) / SATOSHI,
                     HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction()
    : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction &tx)
    : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime) {}

static uint256 ComputeCMutableTransactionHash(const CMutableTransaction &tx) {
    return SerializeHash(tx, SER_GETHASH, 0);
}

TxId CMutableTransaction::GetId() const {
    return TxId(ComputeCMutableTransactionHash(*this));
}

TxHash CMutableTransaction::GetHash() const {
    return TxHash(ComputeCMutableTransactionHash(*this));
}

uint256 CTransaction::ComputeHash() const {
    return SerializeHash(*this, SER_GETHASH, 0);
}

/*static*/ const CTransaction CTransaction::null;

//! This sharedNull is a singleton returned by MakeTransactionRef() (no args).
//! It is a 'fake' shared pointer that points to `null` above, and its deleter
//! is a no-op.
/*static*/ const CTransactionRef CTransaction::sharedNull{&CTransaction::null, [](const CTransaction *){}};

/* private - for constructing the above null value only */
CTransaction::CTransaction() : nVersion{CTransaction::CURRENT_VERSION}, nLockTime{0} {}

/* public */
CTransaction::CTransaction(const CMutableTransaction &tx)
    : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime), hash(ComputeHash()) {}
CTransaction::CTransaction(CMutableTransaction &&tx)
    : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion),
      nLockTime(tx.nLockTime), hash(ComputeHash()) {}

Amount CTransaction::GetValueOut() const {
    Amount nValueOut = Amount::zero();
    for (const auto &tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut)) {
            throw std::runtime_error(std::string(__func__) +
                                     ": value out of range");
        }
    }
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const {
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const {
    std::string str;
    str += strprintf("CTransaction(txid=%s, ver=%d, vin.size=%u, vout.size=%u, "
                     "nLockTime=%u)\n",
                     GetId().ToString().substr(0, 10), nVersion, vin.size(),
                     vout.size(), nLockTime);
    for (const auto &nVin : vin) {
        str += "    " + nVin.ToString() + "\n";
    }
    for (const auto &nVout : vout) {
        str += "    " + nVout.ToString() + "\n";
    }
    return str;
}

bool CTransaction::IsDMA() const {
    if (vin.size() != 1)
        return false;
    if (vout.size() != 2)
        return false;
    if (!nLockTime)
        return false;

    uint32_t height = nLockTime;
    const CTxIn &txIn = vin[0];
    const CTxOut &txOut = vout[0];
    const CTxOut &txSig = vout[1];

    if (!txIn.prevout.IsNull())
        return false;
    if (!txIn.scriptSig.empty())
        return false;
    if (txIn.nSequence != CTxIn::SEQUENCE_FINAL)
        return false;
    if (height < 1 || height >= LOCKTIME_THRESHOLD)
        return false;
    if (txSig.nValue != Amount::zero())
        return false;
    if (txSig.scriptPubKey.size() < 60)
        return false;
    if (txSig.scriptPubKey.size() > 75)
        return false;
    if (txSig.scriptPubKey[0] != OP_RETURN)
        return false;
    if (txOut.nValue > MAX_MINTER_SUBSIDY * COIN)
        return false;
    return true;
}

bool CTransaction::IsDMA(int height) const {
    if (static_cast<int64_t>(nLockTime) != height)
        return false;
    return IsDMA();
}

bool CTransaction::IsCrossChain() const {
    if (vin.size() != 1)
        return false;
    if (vout.size() != 1)
        return false;
    if (!nLockTime)
        return false;

    uint32_t height = nLockTime;
    const CTxIn &txIn = vin[0];
    const CTxOut &txOut = vout[0];
    const CScript &txOutScript = txOut.scriptPubKey;

    if (txIn.prevout.IsNull())
        return false;
    if (txIn.scriptSig.empty())
        return false;
    if (txIn.nSequence != CTxIn::SEQUENCE_FINAL)
        return false;
    if (height < 1 || height >= LOCKTIME_THRESHOLD)
        return false;
    if (!txOutScript.IsCrossChain())
        return false;
    return true;
}
