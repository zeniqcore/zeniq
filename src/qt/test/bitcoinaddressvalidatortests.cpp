// Copyright (c) 2017 The Bitcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bitcoinaddressvalidator.h>
#include <qt/test/bitcoinaddressvalidatortests.h>

#include <chainparams.h>

#include <QValidator>

void BitcoinAddressValidatorTests::inputTests() {
    const auto params = CreateChainParams(CBaseChainParams::ZENIQ);
    const std::string prefix = params->CashAddrPrefix();
    AddressEntryValidator v(prefix, nullptr);

    int unused = 0;
    QString in;

    // Empty string is intermediate.
    in = "";
    QVERIFY(v.validate(in, unused) == QValidator::Intermediate);

    // invalid base58 because of I, invalid cashaddr, currently considered valid
    // anyway.
    in = "ZEEN";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // invalid base58, invalid cashaddr, currently considered valid anyway.
    in = "ZENIQQ";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // invalid base58 because of I, but could be a cashaddr prefix
    in = "ZENQ";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // invalid base58, valid cashaddr
    in = "ZENIQ:QP";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // invalid base58, valid cashaddr, lower case
    in = "zeniq:qp";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // invalid base58, valid cashaddr, mixed case
    in = "zEnIq:Qp";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // valid base58, invalid address
    in = "ZZZZZZZZZZ";
    QVERIFY(v.validate(in, unused) == QValidator::Acceptable);

    // Only alphanumeric chars are accepted.
    in = "%";
    QVERIFY(v.validate(in, unused) == QValidator::Invalid);
}
