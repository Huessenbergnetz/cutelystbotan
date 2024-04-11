// SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
//
// SPDX-License-Identifier: BSD-3-Clause

#include "CutelystBotan/credentialbotan.h"

#include <QTest>

using namespace CutelystBotan;

class CutelystBotanTest final : public QObject
{
    Q_OBJECT
public:
    explicit CutelystBotanTest(QObject *parent = nullptr)
        : QObject{parent}
    {
    }
    ~CutelystBotanTest() final = default;

private slots:
    void initTestCase();
    void testArgon2();
    void testArgon2Wrong();
    void testArgon2InvalidType();
    void benchmarkArgon2();
    void testBcrypt();
    void testBcryptWrong();
    void testBcryptInvalidWorkFactor();
    void benchmarkBcrypt();
    void testPasshash9();
    void testPasshash9Wrong();
    void testPasshash9InvalidWorkFactor();
    void benchmarkPasshash9();
    void testInvalidHashString();

private:
    QString password;
    QString argon2Hash;
    QString bcryptHash;
    QString passhash9Hash;
};

void CutelystBotanTest::initTestCase()
{
    password = u"no one should ever know"_qs;

    argon2Hash = CredentialBotan::createArgon2Password(password);
    QVERIFY(!argon2Hash.isEmpty());

    bcryptHash = CredentialBotan::createBcryptPassword(password);
    QVERIFY(!bcryptHash.isEmpty());

    passhash9Hash = CredentialBotan::createPasshash9Password(password);
    QVERIFY(!passhash9Hash.isEmpty());
}

void CutelystBotanTest::testArgon2()
{
    QVERIFY(CredentialBotan::validatePassword(password, argon2Hash));
}

void CutelystBotanTest::testArgon2Wrong()
{
    QVERIFY(!CredentialBotan::validatePassword(u"some attempt"_qs, argon2Hash));
}

void CutelystBotanTest::testArgon2InvalidType()
{
    constexpr size_t p = 1;
    constexpr size_t m = 262144;
    constexpr size_t i = 1;
    constexpr size_t s = 16;
    constexpr size_t o = 32;

    QVERIFY(CredentialBotan::createArgon2Password(
                password.toUtf8(), CredentialBotan::Type::Invalid, p, m, i, s, o)
                .isEmpty());
    QVERIFY(CredentialBotan::createArgon2Password(
                password.toUtf8(), CredentialBotan::Type::Bcrypt, p, m, i, s, o)
                .isEmpty());
    QVERIFY(CredentialBotan::createArgon2Password(
                password.toUtf8(), CredentialBotan::Type::Passhash9, p, m, i, s, o)
                .isEmpty());
}

void CutelystBotanTest::benchmarkArgon2()
{
    QBENCHMARK
    {
        CredentialBotan::validatePassword(password, argon2Hash);
    }
}

void CutelystBotanTest::testBcrypt()
{
    QVERIFY(CredentialBotan::validatePassword(password, bcryptHash));
}

void CutelystBotanTest::testBcryptWrong()
{
    QVERIFY(!CredentialBotan::validatePassword(u"some attempt"_qs, bcryptHash));
}

void CutelystBotanTest::testBcryptInvalidWorkFactor()
{
    QVERIFY(CredentialBotan::createBcryptPassword(password.toUtf8(), 3, 'a').isEmpty());
    QVERIFY(CredentialBotan::createBcryptPassword(password.toUtf8(), 19, 'a').isEmpty());
}

void CutelystBotanTest::benchmarkBcrypt()
{
    QBENCHMARK
    {
        CredentialBotan::validatePassword(password, bcryptHash);
    }
}

void CutelystBotanTest::testPasshash9()
{
    QVERIFY(CredentialBotan::validatePassword(password, passhash9Hash));
}

void CutelystBotanTest::testPasshash9Wrong()
{
    QVERIFY(!CredentialBotan::validatePassword(u"some attempt"_qs, passhash9Hash));
}

void CutelystBotanTest::testPasshash9InvalidWorkFactor()
{
    QVERIFY(CredentialBotan::createPasshash9Password(
                password.toUtf8(), 0, CredentialBotan::Passhash9Algo::HmacSha1)
                .isEmpty());
    QVERIFY(CredentialBotan::createPasshash9Password(
                password.toUtf8(), 513, CredentialBotan::Passhash9Algo::HmacSha1)
                .isEmpty());
}

void CutelystBotanTest::benchmarkPasshash9()
{
    QBENCHMARK
    {
        CredentialBotan::validatePassword(password, passhash9Hash);
    }
}

void CutelystBotanTest::testInvalidHashString()
{
    QString invalid = argon2Hash;
    invalid.replace(1, 1, 'b');
    QVERIFY(!CredentialBotan::validatePassword(password, invalid));
}

QTEST_MAIN(CutelystBotanTest)

#include "testcutelystbotan.moc"
