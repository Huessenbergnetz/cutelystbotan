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
    void benchmarkArgon2();
    void testBcrypt();
    void benchmarkBcrypt();
    void testPasshash9();
    void benchmarkPasshash9();

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

void CutelystBotanTest::benchmarkPasshash9()
{
    QBENCHMARK
    {
        CredentialBotan::validatePassword(password, passhash9Hash);
    }
}

QTEST_MAIN(CutelystBotanTest)

#include "testcutelystbotan.moc"
