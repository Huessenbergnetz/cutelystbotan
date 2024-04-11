// SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CUTELYSTBOTAN_CREDENTIALBOTAN_H
#define CUTELYSTBOTAN_CREDENTIALBOTAN_H

#include "cutelystbotan_export.h"

#include <Cutelyst/Plugins/Authentication/authentication.h>

namespace CutelystBotan {

class CredentialBotanPrivate;
class CUTELYSTBOTAN_EXPORT CredentialBotan final : public Cutelyst::AuthenticationCredential
{
    Q_OBJECT
    Q_DECLARE_PRIVATE(CredentialBotan) // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    Q_DISABLE_COPY(CredentialBotan)
public:
    explicit CredentialBotan(QObject *parent = nullptr);
    ~CredentialBotan() final;

    enum class Type {
        Invalid   = -1,
        Argon2d   = 0,
        Argon2i   = 1,
        Argon2id  = 2,
        Bcrypt    = 3,
        Passhash9 = 4
    };
    Q_ENUM(Type)

    enum class Passhash9Algo {
        HmacSha1     = 0,
        HmacSha256   = 1,
        CmacBlowfish = 2,
        HmacSha384   = 3,
        HmacSha512   = 4
    };
    Q_ENUM(Passhash9Algo);

    [[nodiscard]] QString passwordField() const;

    void setPasswordField(const QString &fieldName);

    [[nodiscard]] QString passwordPreSalt() const;

    void setPasswordPreSalt(const QString &passwordPreSalt);

    [[nodiscard]] QString passwordPostSalt() const;

    void setPasswordPostSalt(const QString &passwordPostSalt);

    Cutelyst::AuthenticationUser authenticate(Cutelyst::Context *c,
                                              Cutelyst::AuthenticationRealm *realm,
                                              const Cutelyst::ParamsMultiMap &authinfo) final;

    static bool validatePassword(const QByteArray &password, const QByteArray &correctHash);

    inline static bool validatePassword(const QString &password, const QString &correctHash);

    static QByteArray createArgon2Password(const QByteArray &password,
                                           Type type,
                                           size_t parallelization,
                                           size_t memory,
                                           size_t iterations,
                                           size_t saltLength,
                                           size_t outputLength);

    static QByteArray createArgon2Password(const QByteArray &password);

    inline static QString createArgon2Password(const QString &password);

    static QByteArray
        createBcryptPassword(const QByteArray &password, uint16_t workFactor, char version);

    static QByteArray createBcryptPassword(const QByteArray &password);

    inline static QString createBcryptPassword(const QString &password);

    static QByteArray createPasshash9Password(const QByteArray &password,
                                              uint16_t workFactor,
                                              Passhash9Algo algorithm);

    static QByteArray createPasshash9Password(const QByteArray &password);

    inline static QString createPasshash9Password(const QString &password);

private:
    const std::unique_ptr<CredentialBotanPrivate> d_ptr;
};

inline bool CredentialBotan::validatePassword(const QString &password, const QString &correctHash)
{
    return validatePassword(password.toUtf8(), correctHash.toUtf8());
}

inline QString CredentialBotan::createArgon2Password(const QString &password)
{
    return QString::fromLatin1(CredentialBotan::createArgon2Password(password.toUtf8()));
}

inline QString CredentialBotan::createBcryptPassword(const QString &password)
{
    return QString::fromLatin1(CredentialBotan::createBcryptPassword(password.toUtf8()));
}

inline QString CredentialBotan::createPasshash9Password(const QString &password)
{
    return QString::fromLatin1(CredentialBotan::createPasshash9Password(password.toUtf8()));
}

} // namespace CutelystBotan

#endif // CUTELYSTBOTAN_CREDENTIALBOTAN_H
