// SPDX-FileCopyrightText: (C) 2024 Matthias Fehring <https://www.huessenbergnetz.de>
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef CUTELYSTBOTAN_CREDENTIALBOTAN_H
#define CUTELYSTBOTAN_CREDENTIALBOTAN_H

#include "cutelystbotan_export.h"

#include <Cutelyst/Plugins/Authentication/authentication.h>

namespace CutelystBotan {

class CredentialBotanPrivate;

/**
 * \headerfile credentialbotan.h <CutelystBotan/credentialbotan.h>
 * \brief Use password based authentication from Botan library to authenticate a user.
 *
 * This credential provider authenticates a user with authentication information provided
 * by for example a HTML login formular or another source for login data. It uses the
 * <A HREF="">Botan</A> library to provide different algorithms for password hashing.
 *
 * More information about password hashing with Botan can be found
 * <A HREF="https://botan.randombit.net/handbook/api_ref/passhash.html">here</A>.
 */
class CUTELYSTBOTAN_EXPORT CredentialBotan final : public Cutelyst::AuthenticationCredential
{
    Q_OBJECT
    Q_DECLARE_PRIVATE(CredentialBotan) // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    Q_DISABLE_COPY(CredentialBotan)
public:
    /**
     * Constructs a new %CredentialBotan object with the given \a parent.
     */
    explicit CredentialBotan(QObject *parent = nullptr);
    /**
     * Destroys the %CredentialBotan object.
     */
    ~CredentialBotan() final;

    /**
     * Supported password hashing algorithms.
     */
    enum class Type {
        Invalid   = -1, /**< Invalid. */
        Argon2d   = 0,  /**< Argon2d password hashing. */
        Argon2i   = 1,  /**< Argon2i password hashing. */
        Argon2id  = 2,  /**< Argon2id password hashing (\b recommended). */
        Bcrypt    = 3,  /**< Bcrypt password hashing. */
        Passhash9 = 4   /**< Based on the PBKDF2 algorithm. Note that this is not compatible
                             with the internal PBKDF2 algorithm of %Cutelyst. */
    };
    Q_ENUM(Type)

    /**
     * Cryptographic hash function and MAC used for Passhash9 algorithm.
     */
    enum class Passhash9Algo {
        HmacSha1     = 0, /**< HMAC with SHA-1. */
        HmacSha256   = 1, /**< HMAC with SHA-256 (SHA2). */
        CmacBlowfish = 2, /**< CMAC with Blowfish */
        HmacSha384   = 3, /**< HMAC with SHA-384 (SHA2). */
        HmacSha512   = 4  /**< HMAC with SHA-512 (SHA2). */
    };
    Q_ENUM(Passhash9Algo);

    /**
     * Returns the field to look for when authentication the user.
     * By default, this is "password".
     * \sa authenticate(), setPasswordField()
     */
    [[nodiscard]] QString passwordField() const;

    /**
     * Sets the field to look for when authenticating the user.
     * \sa authenticate(), passwordField()
     */
    void setPasswordField(const QString &fieldName);

    /**
     * Returns the salt string to be prepended to the password.
     * \sa setPasswordPreSalt()
     */
    [[nodiscard]] QString passwordPreSalt() const;

    /**
     * Sets the salt string to be prepended to the password.
     * \sa passwordPreSalt()
     */
    void setPasswordPreSalt(const QString &passwordPreSalt);

    /**
     * Returns the salt string to be appended to the password.
     * \sa setPasswordPostSalt()
     */
    [[nodiscard]] QString passwordPostSalt() const;

    /**
     * Sets the salt string to be appended to the password.
     * \sa passwordPostSalt()
     */
    void setPasswordPostSalt(const QString &passwordPostSalt);

    /**
     * Tries to authenticate the user from the \a authinfo by searching it in the given \a realm.
     * If found, the password will be checked by getting it from the keys named by passwordField()
     * in the \a authinfo and in the AuthenticationUser found by the \a realm. On success,
     * a not null AuthenticationUser object will be returned.
     */
    Cutelyst::AuthenticationUser authenticate(Cutelyst::Context *c,
                                              Cutelyst::AuthenticationRealm *realm,
                                              const Cutelyst::ParamsMultiMap &authinfo) final;

    /**
     * Validates the given \a password against the \a correctHash and returns \c true on success.
     */
    static bool validatePassword(const QByteArray &password, const QByteArray &correctHash);

    /**
     * Validates the given \a password against the \a correctHash and returns \c true on success.
     */
    inline static bool validatePassword(const QString &password, const QString &correctHash);

    /**
     * Returns a password hash using the Argon2 algorithm specified by \a type of \a outputLength
     * using a salt of \a saltLength.
     *
     * Argon2 is the winner of the PHC (Password Hashing Competition) and provides a tunable memory
     * hard password hash. It has a standard string encoding, which looks like:
     *
     * "$argon2id$v=19$m=262144,t=1,p=1$8r5BhdM07OhW6KWZrxenSw$l6+i7J1g5XOzw/tqQVZzb1LMH1QzrWQRLlB+72kO4JA".
     *
     * Argon2 has three tunable parameters: \a memory, \a parallelization, and \a iterations.
     * \a memory gives the total memory consumption of the algorithm in kilobytes. Increasing
     * \a parallelization increases the available parallelism of the computation. The
     * \a iterations parameter gives the number of passes which are made over the data.
     *
     * There are three variants of Argon2, namely Argon2d, Argon2i and Argon2id. Argon2d uses data
     * dependent table lookups with may leak information about the password via side channel
     * attacks, and is not recommended for password hashing. Argon2i uses data independent table
     * lookups and is immune to these attacks, but at the cost of requiring higher \a iterations
     * for security. Argon2id uses a hybrid approach which is thought to be highly secure. The
     * algorithm designers recommend using Argon2id with \a iterations and \a parallelization
     * both equal to \c 1 and \a memory set to the largest amount of memory usable in your
     * environment.
     *
     * You can also use tune() to get parameters that fit to a specified runtime of the algorithm.
     *
     * \param password          The password to hash.
     * \param type              Argon2id (recommended), Argon2i or Argon2d.
     * \param parallelization   Available parallelism of the computation.
     * \param memory            Total memory consumption in kilobytes.
     * \param iterations        Number of passes which are made over the data.
     * \param saltLength        Length of the salt.
     * \param outputLength      Output length.
     * \return The hashed password on success, otherwise an empty byte array.
     *
     * \sa tuneArgon2()
     */
    static QByteArray createArgon2Password(const QByteArray &password,
                                           Type type,
                                           size_t parallelization,
                                           size_t memory,
                                           size_t iterations,
                                           size_t saltLength,
                                           size_t outputLength);

    /**
     * Returns a password hashed with Argon2id, parallelization = 1, iterations = 1 and
     * maximum memory usage of 256MB. The salt length is 16 and the output length is 32.
     */
    static QByteArray createArgon2Password(const QByteArray &password);

    /**
     * Returns a password hashed with Argon2id, parallelization = 1, iterations = 1 and
     * maximum memory usage of 256MB. The salt length is 16 and the output length is 32.
     */
    inline static QString createArgon2Password(const QString &password);

    /**
     * Returns a password hash using the Bcrypt algorithm with the given \a workFactor and
     * \a version.
     *
     * Bcrypt is a password hashing scheme originally designed for use in OpenBSD, but numerous
     * other implementations exist.
     *
     * It has the advantage that it requires a small amount (4K) of fast RAM to compute, which
     * can make hardware password cracking somewhat more expensive.
     *
     * Bcrypt provides outputs that look like this:
     *
     * "$2a$12$7KIYdyv8Bp32WAvc.7YvI.wvRlyVn0HP/EhPmmOyMQA4YKxINO0p2"
     *
     * \note Due to the design of bcrypt, the password is effectively truncated at 72 characters;
     * further characters are ignored and do not change the hash. To support longer passwords, one
     * common approach is to pre-hash the password with SHA-256, then run bcrypt using the hex
     * or base64 encoding of the hash as the password. (Many bcrypt implementations truncate the
     * password at the first NULL character, so hashing the raw binary SHA-256 may cause problems.
     * Botan’s bcrypt implementation will hash whatever values are given in the \a password
     * including any embedded NULLs so this is not an issue, but might cause interop problems if
     * another library needs to validate the password hashes.)
     *
     * Higher \a workFactor increase the amount of time the algorithm runs, increasing the cost of
     * cracking attempts. The increase is exponential, so a \a workFactor of 12 takes roughly twice
     * as long as \a workFactor 11.
     *
     * It is recommended to set the \a workFactor as high as your system can tolerate (from a
     * performance and latency perspective) since higher \a workFactors greatly improve the
     * security against GPU-based attacks. For example, for protecting high value administrator
     * passwords, consider using \a workFactor 15 or 16; at these \a workFactors each bcrypt
     * computation takes several seconds. Since admin logins will be relatively uncommon, it
     * might be acceptable for each login attempt to take some time. As of 2018, a good password
     * cracking rig (with 8 NVIDIA 1080 cards) can attempt about 1 billion bcrypt computations
     * per month for \a workFactor 13. For \a workFactor 12, it can do twice as many. For
     * \a workFactor 15, it can do only one quarter as many attempts.
     *
     * \note Due to bugs affecting various implementations of bcrypt, several different variants
     * of the algorithm are defined. As of 2.7.0 Botan supports generating (or checking) the
     * 2a, 2b, and 2y variants. Since Botan has never been affected by any of the bugs which
     * necessitated these version upgrades, all three versions are identical beyond the \a version
     * identifier. Which variant to use is controlled by the \a version argument.
     *
     * The bcrypt \a workFactor must be at least 4 (though at this \a workFactor bcrypt is not
     * very secure). The bcrypt format allows up to 31, but Botan currently rejects all
     * \a workFactors greater than 18 since even that \a workFactor requires roughly 15 seconds
     * of computation on a fast machine.
     *
     * @param password      The password to hash.
     * @param workFactor    The work factor used for computation, between 4 and 18.
     * @param version       The version to used (see note above).
     * @return The hashed password on success, otherwise an empty byte array.
     */
    static QByteArray
        createBcryptPassword(const QByteArray &password, uint16_t workFactor, char version = 'a');

    /**
     * Returns a password hashed with Bcrypt using a work factor of \c 12.
     */
    static QByteArray createBcryptPassword(const QByteArray &password);

    /**
     * Returns a password hashed with Bcrypt using a work factor of \c 12.
     */
    inline static QString createBcryptPassword(const QString &password);

    /**
     * Returns a password hashed with the Passhash9 algorithm which is based on PBKDF2 using
     * the given \a workFactor and hashing \a algorithm.
     *
     * Passhash9 hashes look like:
     *
     * "$9$AAAKxwMGNPSdPkOKJS07Xutm3+1Cr3ytmbnkjO6LjHzCMcMQXvcT"
     *
     * \note This is not compatible with the internal PBKDF2 implementation of %Cutelyst.
     *
     * You can also use tune() to get parameters that fit to a specified runtime of the algorithm.
     *
     * @param password      The password to hash.
     * @param workFactor    Iterations to use. Will be multiplied by 10,000.
     * @param algorithm     The MAC and hashing algorithm to use.
     * @return The hashed password on success, otherwise an empty byte array.
     */
    static QByteArray createPasshash9Password(const QByteArray &password,
                                              uint16_t workFactor,
                                              Passhash9Algo algorithm);

    /**
     * Returns a password hashed with Passhash9 using HMAC(SHA-256) algorithm
     * and 200.000 iterations (workFactor set to 20).
     */
    static QByteArray createPasshash9Password(const QByteArray &password);

    /**
     * Returns a password hashed with Passhash9 using HMAC(SHA-256) algorithm
     * and 200.000 iterations (workFactor set to 20).
     */
    inline static QString createPasshash9Password(const QString &password);

    /**
     * Contains tuning parameters returned by tune().
     */
    struct Params {
        /**
         * Iterations for Argon2 or work factor for Bcrypt.
         */
        size_t iterations{0};
        /**
         * Memory for Argon2 in kilobyte. Contains \c 0 for Bcrypt.
         */
        size_t memory{0};
        /**
         * Parallelism for Argon2. Contains \c 0 for Bcrypt.
         */
        size_t parallelism{0};
    };

    /**
     * Returns tuning parameters for Argon2 and Passhash9 to get settings for the specified
     * computation \a runtime.
     * @param type              Hashing algorithm type.
     * @param outputLength      The output length.
     * @param runtime           The expected runtime.
     * @param maxMemoryUsageMb  The maximum memory usage.
     * @param ph9Algo           The HMAC and hash algo used by Passhash9.
     * @return Params struct containing the tuned parameters.
     */
    static Params tune(Type type,
                       size_t outputLength,
                       std::chrono::milliseconds runtime,
                       size_t maxMemoryUsageMb = 0,
                       Passhash9Algo ph9Algo   = Passhash9Algo::HmacSha512);

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
