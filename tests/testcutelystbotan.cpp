// SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
//
// SPDX-License-Identifier: BSD-3-Clause

#include "CutelystBotan/credentialbotan.h"

#include <QTest>

using namespace CutelystBotan;
using namespace Qt::Literals::StringLiterals;

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

    void testTuneArgon2();
    void testTunePasshash9();

    void testSetPasswordField();
    void testSetPasswordPreSalt();
    void testSetPasswordPostSalt();
    void testDefaultConstructor();

private:
    QString password;
    QString argon2Hash;
    QString bcryptHash;
    QString passhash9Hash;
};

void CutelystBotanTest::initTestCase()
{
    password = u"no one should ever know"_s;

    argon2Hash = CredentialBotan::createArgon2Password(password);
    QVERIFY(argon2Hash.startsWith(u"$argon2"_s));

    bcryptHash = CredentialBotan::createBcryptPassword(password);
    QVERIFY(bcryptHash.startsWith(u"$2"_s));

    passhash9Hash = CredentialBotan::createPasshash9Password(password);
    QVERIFY(passhash9Hash.startsWith(u"$9$"_s));
}

void CutelystBotanTest::testArgon2()
{
    QVERIFY(CredentialBotan::validatePassword(password, argon2Hash));
}

void CutelystBotanTest::testArgon2Wrong()
{
    QVERIFY(!CredentialBotan::validatePassword(u"some attempt"_s, argon2Hash));
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
        auto hash = CredentialBotan::validatePassword(password, argon2Hash);
    }
}

void CutelystBotanTest::testBcrypt()
{
    QVERIFY(CredentialBotan::validatePassword(password, bcryptHash));
}

void CutelystBotanTest::testBcryptWrong()
{
    QVERIFY(!CredentialBotan::validatePassword(u"some attempt"_s, bcryptHash));
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
        auto hash = CredentialBotan::validatePassword(password, bcryptHash);
    }
}

void CutelystBotanTest::testPasshash9()
{
    QVERIFY(CredentialBotan::validatePassword(password, passhash9Hash));
}

void CutelystBotanTest::testPasshash9Wrong()
{
    QVERIFY(!CredentialBotan::validatePassword(u"some attempt"_s, passhash9Hash));
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
        auto hash = CredentialBotan::validatePassword(password, passhash9Hash);
    }
}

void CutelystBotanTest::testTuneArgon2()
{
    auto params = CredentialBotan::tune(
        CredentialBotan::Type::Argon2id, 32, std::chrono::milliseconds{300}, 256);
    QVERIFY(params.memory > 0);
    QVERIFY(params.iterations > 0);
    QVERIFY(params.parallelism > 0);
}

void CutelystBotanTest::testTunePasshash9()
{
    auto params = CredentialBotan::tune(CredentialBotan::Type::Passhash9,
                                        32,
                                        std::chrono::milliseconds{300},
                                        256,
                                        CredentialBotan::Passhash9Algo::HmacSha512);
    QCOMPARE(params.memory, 0);
    QVERIFY(params.iterations > 1);
    QCOMPARE(params.parallelism, 0);
}

void CutelystBotanTest::testInvalidHashString()
{
    QString invalid = argon2Hash;
    invalid.replace(1, 1, 'b');
    QVERIFY(!CredentialBotan::validatePassword(password, invalid));
}

void CutelystBotanTest::testSetPasswordField()
{
    CredentialBotan bt;
    const QString pwfield = u"passwort"_s;
    bt.setPasswordField(pwfield);
    QCOMPARE(bt.passwordField(), pwfield);
}

void CutelystBotanTest::testSetPasswordPreSalt()
{
    CredentialBotan bt;
    const QString salt = u"Lorem ipsum"_s;
    bt.setPasswordPreSalt(salt);
    QCOMPARE(bt.passwordPreSalt(), salt);
}

void CutelystBotanTest::testSetPasswordPostSalt()
{
    CredentialBotan bt;
    const QString salt = u"Trallala"_s;
    bt.setPasswordPostSalt(salt);
    QCOMPARE(bt.passwordPostSalt(), salt);
}

void CutelystBotanTest::testDefaultConstructor()
{
    CredentialBotan bt;
    QCOMPARE(bt.passwordField(), u"password"_s);
    QVERIFY(bt.passwordPreSalt().isEmpty());
    QVERIFY(bt.passwordPostSalt().isEmpty());
}

QTEST_MAIN(CutelystBotanTest)

#include "testcutelystbotan.moc"
