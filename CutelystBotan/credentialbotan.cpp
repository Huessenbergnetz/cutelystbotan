// SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
//
// SPDX-License-Identifier: BSD-3-Clause

#include "credentialbotan.h"

#include <Cutelyst/Plugins/Authentication/authenticationrealm.h>
#include <botan/argon2.h>
#include <botan/bcrypt.h>
#include <botan/passhash9.h>
#include <botan/system_rng.h>
#include <memory>
#include <string>

#include <QLoggingCategory>

#if defined(QT_DEBUG)
Q_LOGGING_CATEGORY(C_CREDENTIALBOTAN, "cutelyst.plugin.credentialbotan")
#else
Q_LOGGING_CATEGORY(C_CREDENTIALBOTAN, "cutelyst.plugin.credentialbotan", QtWarningMsg)
#endif

namespace CutelystBotan {

class CredentialBotanPrivate
{
public:
    bool checkPassword(const Cutelyst::AuthenticationUser &user,
                       const Cutelyst::ParamsMultiMap &authinfo);
    static CredentialBotan::Type checkPwType(const QByteArray &hashedPw);

    QString passwordField{u"password"_qs};
    QString passwordPreSalt;
    QString passwordPostSalt;
};

} // namespace CutelystBotan

using namespace CutelystBotan;

CredentialBotan::CredentialBotan(QObject *parent)
    : Cutelyst::AuthenticationCredential{parent}
    , d_ptr{new CredentialBotanPrivate}
{
}

CredentialBotan::~CredentialBotan() = default;

QString CredentialBotan::passwordField() const
{
    Q_D(const CredentialBotan);
    return d->passwordField;
}

void CredentialBotan::setPasswordField(const QString &fieldName)
{
    Q_D(CredentialBotan);
    d->passwordField = fieldName;
}

QString CredentialBotan::passwordPreSalt() const
{
    Q_D(const CredentialBotan);
    return d->passwordPreSalt;
}

void CredentialBotan::setPasswordPreSalt(const QString &passwordPreSalt)
{
    Q_D(CredentialBotan);
    d->passwordPreSalt = passwordPreSalt;
}

QString CredentialBotan::passwordPostSalt() const
{
    Q_D(const CredentialBotan);
    return d->passwordPostSalt;
}

void CredentialBotan::setPasswordPostSalt(const QString &passwordPostSalt)
{
    Q_D(CredentialBotan);
    d->passwordPostSalt = passwordPostSalt;
}

Cutelyst::AuthenticationUser CredentialBotan::authenticate(Cutelyst::Context *c,
                                                           Cutelyst::AuthenticationRealm *realm,
                                                           const Cutelyst::ParamsMultiMap &authinfo)
{
    Q_D(CredentialBotan);
    const auto user = realm->findUser(c, authinfo);
    if (!user.isNull()) {
        if (d->checkPassword(user, authinfo)) {
            return user;
        }
        qCDebug(C_CREDENTIALBOTAN) << "Password didn’t match";
    }

    qCDebug(C_CREDENTIALBOTAN) << "Unable to locate a user matching user info provided in realm.";

    return {};
}

bool CredentialBotan::validatePassword(const QByteArray &password, const QByteArray &correctHash)
{
    const auto type = CredentialBotanPrivate::checkPwType(correctHash);

    if (type == Type::Argon2id || type == Type::Argon2i || type == Type::Argon2d) {
        const std::string hash = correctHash.toStdString();
        return Botan::argon2_check_pwhash(password.constData(), password.size(), hash);
    } else if (type == Type::Bcrypt) {
        const std::string hash = correctHash.toStdString();
        const std::string pw   = password.toStdString();
        return Botan::check_bcrypt(pw, hash);
    } else if (type == Type::Passhash9) {
        const std::string hash = correctHash.toStdString();
        const std::string pw   = password.toStdString();
        return Botan::check_passhash9(pw, hash);
    }

    qCCritical(C_CREDENTIALBOTAN)
        << "Invalid password hash. Does not contain a supported hash identifier.";

    return false;
}

QByteArray CredentialBotan::createArgon2Password(const QByteArray &password,
                                                 Type type,
                                                 size_t parallelization,
                                                 size_t memory,
                                                 size_t iterations,
                                                 size_t saltLength,
                                                 size_t outputLength)
{
    auto argonType = static_cast<uint8_t>(Type::Argon2id);
    switch (type) {
    case Type::Argon2id:
        break;
    case Type::Argon2i:
        argonType = static_cast<uint8_t>(Type::Argon2i);
        break;
    case Type::Argon2d:
        argonType = static_cast<uint8_t>(Type::Argon2d);
        break;
    default:
        qCCritical(C_CREDENTIALBOTAN)
            << "Failed to create Argon2 password hash: invalid type selected.";
        return {};
    }

    auto rng = std::make_unique<Botan::System_RNG>();

    return QByteArray::fromStdString(Botan::argon2_generate_pwhash(password.constData(),
                                                                   password.size(),
                                                                   *rng.get(),
                                                                   parallelization,
                                                                   memory,
                                                                   iterations,
                                                                   argonType,
                                                                   saltLength,
                                                                   outputLength));
}

QByteArray CredentialBotan::createArgon2Password(const QByteArray &password)
{
    constexpr size_t parallelization = 1;
    constexpr size_t memory          = 262144;
    constexpr size_t iterations      = 1;
    constexpr size_t saltLength      = 16;
    constexpr size_t outputLength    = 32;

    return CredentialBotan::createArgon2Password(
        password, Type::Argon2id, parallelization, memory, iterations, saltLength, outputLength);
}

QByteArray CredentialBotan::createBcryptPassword(const QByteArray &password,
                                                 uint16_t workFactor,
                                                 char version)
{
    constexpr uint16_t minWorkFactor = 4;
    constexpr uint16_t maxWorkFactor = 18;
    if ((workFactor < minWorkFactor) || (workFactor > maxWorkFactor)) {
        qCCritical(C_CREDENTIALBOTAN)
            << "Failed to create Bcrypt password hash: invalid work factor < 4 or > 18.";
        return {};
    }

    const std::string pw = password.toStdString();

    auto rng = std::make_unique<Botan::System_RNG>();

    return QByteArray::fromStdString(Botan::generate_bcrypt(pw, *rng.get(), workFactor, version));
}

QByteArray CredentialBotan::createBcryptPassword(const QByteArray &password)
{
    constexpr uint16_t defaultWorkFactor = 12;
    return CredentialBotan::createBcryptPassword(password, defaultWorkFactor, 'a');
}

QByteArray CredentialBotan::createPasshash9Password(const QByteArray &password,
                                                    uint16_t workFactor,
                                                    Passhash9Algo algorithm)
{
    constexpr uint16_t minWorkFactor = 1;
    constexpr uint16_t maxWorkFactor = 512;
    if ((workFactor < minWorkFactor) || (workFactor > maxWorkFactor)) {
        qCCritical(C_CREDENTIALBOTAN)
            << "Failed to create Passhash9 password hash: invalid work factor < 1 or > 512.";
        return {};
    }

    auto alg_id = static_cast<uint8_t>(Passhash9Algo::HmacSha512);
    switch (algorithm) {
    case Passhash9Algo::HmacSha512:
        break;
    case Passhash9Algo::HmacSha384:
        alg_id = static_cast<uint8_t>(Passhash9Algo::HmacSha384);
        break;
    case Passhash9Algo::CmacBlowfish:
        alg_id = static_cast<uint8_t>(Passhash9Algo::CmacBlowfish);
        break;
    case Passhash9Algo::HmacSha256:
        alg_id = static_cast<uint8_t>(Passhash9Algo::HmacSha256);
        break;
    case Passhash9Algo::HmacSha1:
        alg_id = static_cast<uint8_t>(Passhash9Algo::HmacSha1);
        break;
    }

    const std::string pw = password.toStdString();

    auto rng = std::make_unique<Botan::System_RNG>();

    return QByteArray::fromStdString(Botan::generate_passhash9(pw, *rng.get(), workFactor, alg_id));
}

QByteArray CredentialBotan::createPasshash9Password(const QByteArray &password)
{
    constexpr uint16_t defaultWorkFactor = 20;
    return CredentialBotan::createPasshash9Password(
        password, defaultWorkFactor, Passhash9Algo::HmacSha512);
}

CredentialBotan::Params CredentialBotan::tune(Type type,
                                              size_t outputLength,
                                              std::chrono::milliseconds runtime,
                                              size_t maxMemoryUsageMb,
                                              Passhash9Algo ph9Algo)
{
    std::string algo;

    switch (type) {
    case Type::Argon2id:
        algo = "Argon2id";
        break;
    case Type::Argon2i:
        algo = "Argon2i";
        break;
    case Type::Argon2d:
        algo = "Argon2d";
        break;
    case Type::Passhash9:
        break;
    case Type::Bcrypt:
    case Type::Invalid:
        qCCritical(C_CREDENTIALBOTAN) << "Currently only Argon2 tuning is supported.";
        return {};
    }

    if (type == Type::Passhash9) {
        switch (ph9Algo) {
        case Passhash9Algo::HmacSha1:
            algo = "PBKDF2(HMAC(SHA-1))";
            break;
        case Passhash9Algo::HmacSha256:
            algo = "PBKDF2(HMAC(SHA-256))";
            break;
        case Passhash9Algo::CmacBlowfish:
            algo = "PBKDF2(CMAC(Blowfish))";
            break;
        case Passhash9Algo::HmacSha384:
            algo = "PBKDF2(HMAC(SHA-384))";
            break;
        case Passhash9Algo::HmacSha512:
            algo = "PBKDF2(HMAC(SHA-512))";
            break;
        }
    }

    auto family = Botan::PasswordHashFamily::create(algo);
    auto hash   = family->tune(outputLength, runtime, maxMemoryUsageMb);

    return {type == Type::Passhash9 ? hash->iterations() / 10'000 : hash->iterations(),
            hash->memory_param(),
            hash->parallelism()};
}

bool CredentialBotanPrivate::checkPassword(const Cutelyst::AuthenticationUser &user,
                                           const Cutelyst::ParamsMultiMap &authinfo)
{
    QString password             = authinfo.value(passwordField);
    const QString storedPassword = user.value(passwordField).toString();

    if (!passwordPreSalt.isEmpty()) {
        password.prepend(passwordPreSalt);
    }

    if (!passwordPostSalt.isEmpty()) {
        password.append(passwordPostSalt);
    }

    return CredentialBotan::validatePassword(password.toUtf8(), storedPassword.toUtf8());
}

CredentialBotan::Type CredentialBotanPrivate::checkPwType(const QByteArray &hashedPw)
{
    if (hashedPw.startsWith("$argon2id$")) {
        return CredentialBotan::Type::Argon2id;
    } else if (hashedPw.startsWith("$argon2i$")) {
        return CredentialBotan::Type::Argon2i;
    } else if (hashedPw.startsWith("$argon2d$")) {
        return CredentialBotan::Type::Argon2d;
    } else if (hashedPw.startsWith("$2")) {
        return CredentialBotan::Type::Bcrypt;
    } else if (hashedPw.startsWith("$9$")) {
        return CredentialBotan::Type::Passhash9;
    }

    return CredentialBotan::Type::Invalid;
}

#include "moc_credentialbotan.cpp"
