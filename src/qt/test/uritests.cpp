// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <chainparams.h>
#include <config.h>
#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTestsCashAddr() {
    const auto params = CreateChainParams(CBaseChainParams::ZENIQ);

    SendCoinsRecipient rv;
    QUrl uri;
    QString scheme = QString::fromStdString(params->CashAddrPrefix());
    uri.setUrl(QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?"
                       "req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == Amount::zero());

    uri.setUrl(
        QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?label="
                "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == Amount::zero());

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000 * SATOSHI);

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000 * SATOSHI);

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?amount=100&"
        "label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.amount == int64_t(10000000000) * SATOSHI);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?message="
        "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.label == QString());

    QVERIFY(
        GUIUtil::parseBitcoinURI(scheme,
                                 "zeniq://"
                                 "qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?"
                                 "message=Wikipedia Example Address",
                                 &rv));
    QVERIFY(rv.address ==
            QString("zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?req-message="
        "Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?amount=1,"
        "000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));

    uri.setUrl(QString(
        "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0?amount=1,"
        "000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(scheme, uri, &rv));
}

void URITests::uriTestFormatURI() {
    const auto params = CreateChainParams(CBaseChainParams::ZENIQ);

    {
        SendCoinsRecipient r;
        r.address = "zeniq:qpm2qsznhks23z7629mms6s4cwef74vcwvztr66ek0";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(*params, r);
        QVERIFY(uri == "mSzb231MK1SdancRR3XPnR8BmoGP5A5W3D?message=test");
    }

    {
        // Garbage goes through (address checksum is invalid)
        SendCoinsRecipient r;
        r.address = "mXzb231MK1SdancRR3XPnR8BMoGP5A5W3D";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(*params, r);
        QVERIFY(uri == "mXzb231MK1SdancRR3XPnR8BMoGP5A5W3D?message=test");
    }

    {
        // Legacy addresses are not converted.
        SendCoinsRecipient r;
        r.address = "mHnSXPWAAGoRLjuVgry2LeGcaFgx6rdhV4";
        r.message = "test";
        QString uri = GUIUtil::formatBitcoinURI(*params, r);
        QVERIFY(uri == "mHnSXPWAAGoRLjuVgry2LeGcaFgx6rdhV4?"
                       "message=test");
    }
}
