<?php
declare(strict_types=1);
namespace Soatok\Minisign\Core;

use ParagonIE\ConstantTime\{
    Base64,
    Binary
};
use Soatok\Minisign\Exceptions\{
    MinisignCryptoException,
    MinisignException,
    MinisignFileException
};
use Soatok\Minisign\Minisign;

/**
 * Class SecretKey
 * @package Soatok\Minisign
 */
class SecretKey
{
    /** @var string $checksumAlgorithm */
    private $checksumAlgorithm = Minisign::ALG_BLAKE2;
    /** @var string $kdfAlgorithm */
    private $kdfAlgorithm = Minisign::ALG_SCRYPT;
    /** @var string $signatureAlgorithm */
    private $signatureAlgorithm = Minisign::ALG_EDDSA;

    /** @var int $kdfMemLimit */
    private $kdfMemLimit = SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE;
    /** @var int $kdfOpsLimit */
    private $kdfOpsLimit = SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE;

    /** @var string $untrustedComment */
    private $untrustedComment = 'minisign encrypted secret key';
    /** @var string $keyId */
    private $keyId = '';
    /** @var string $ed25519pk */
    private $ed25519pk = '';
    /** @var string $ed25519sk */
    private $ed25519sk = '';

    /**
     * Deserialize on destruct.
     */
    public function __destruct()
    {
        \sodium_memzero($this->ed25519sk);
    }

    /**
     * Deserialize a minisign secret key from the keyfile contents and password.
     *
     * @param string $contents
     * @param string $password
     * @return self
     * @throws MinisignException
     * @throws \SodiumException
     */
    public static function deserialize(string $contents, string $password): self
    {
        if (!\preg_match(Minisign::REGEX, $contents, $m)) {
            throw new MinisignFileException('Invalid secret key format');
        }
        $untrusted = $m[1];
        $decoded = Base64::decode($m[2]);
        $sigAlg = Binary::safeSubstr($decoded, 0, 2);
        $kdfAlg = Binary::safeSubstr($decoded, 2, 2);
        $cksAlg = Binary::safeSubstr($decoded, 4, 2);
        $kdfSalt = Binary::safeSubstr($decoded, 6, 32);
        $packedOpsLimit = Binary::safeSubstr($decoded, 38, 4);
        $packedMemLimit = Binary::safeSubstr($decoded, 46, 4);
        $kdfOpsLimit = (int) \unpack('V', $packedOpsLimit)[1];
        $kdfMemLimit = (int) \unpack('V', $packedMemLimit)[1];
        $kdfOutput = self::kdf($kdfAlg, $password, $kdfSalt, $kdfOpsLimit, $kdfMemLimit);
        \sodium_memzero($password);
        $remainder = Binary::safeSubstr($decoded, 54, 104) ^ $kdfOutput;
        $keyId = Binary::safeSubstr($remainder, 0, 8);
        $ed25519sk = Binary::safeSubstr($remainder, 8, 32);
        $ed25519pk = Binary::safeSubstr($remainder, 40, 32);
        $checksum = Binary::safeSubstr($remainder, 72, 32);

        // Recalculate checksum
        $calcCsum = \sodium_crypto_generichash(
            $sigAlg . $keyId . $ed25519sk . $ed25519pk
        );
        if (!\hash_equals($calcCsum, $checksum)) {
            throw new MinisignCryptoException('Checksum failed');
        }

        $self = new SecretKey();
        $self->signatureAlgorithm = $sigAlg;
        $self->kdfAlgorithm = $kdfAlg;
        $self->checksumAlgorithm = $cksAlg;
        $self->kdfOpsLimit = $kdfOpsLimit;
        $self->kdfMemLimit = $kdfMemLimit;
        $self->ed25519sk = $ed25519sk . $ed25519pk;
        $self->ed25519pk = $ed25519pk;
        $self->untrustedComment = $untrusted;
        $self->keyId = $keyId;
        return $self;
    }

    /**
     * Deserialize a minisign secret key from the key file and password.
     *
     * @param string $filePath
     * @param string $password
     * @return self
     * @throws MinisignException
     * @throws \SodiumException
     */
    public static function fromFile(string $filePath, string $password): self
    {
        if (empty($filePath)) {
            $filePath = Minisign::getHomeDir() . '/.minisign/minisign.key';
        }
        if (!\is_readable($filePath)) {
            throw new MinisignFileException('File is not readable: ' . $filePath);
        }
        $contents = \file_get_contents($filePath);
        if (!\is_string($contents)) {
            throw new MinisignFileException('File could not be read: ' . $filePath);
        }
        return self::deserialize($contents, $password);
    }

    /**
     * Generate a new Minsign secret key.
     *
     * @return self
     * @throws \SodiumException
     */
    public static function generate(): self
    {
        $keypair = \sodium_crypto_sign_keypair();
        $ed25519sk = \sodium_crypto_sign_secretkey($keypair);
        $ed25519pk = \sodium_crypto_sign_publickey($keypair);
        $keyId = \random_bytes(8);

        $self = new self();
        $self->ed25519sk = $ed25519sk;
        $self->ed25519pk = $ed25519pk;
        $self->keyId = $keyId;
        return $self;
    }

    /**
     * Perform the KDF algorithm.
     *
     * @param string $alg
     * @param string $pw
     * @param string $salt
     * @param int $ops
     * @param int $mem
     * @return string
     * @throws MinisignCryptoException
     * @throws \SodiumException
     */
    protected static function kdf(string $alg, string $pw, string $salt, int $ops, int $mem): string
    {
        if ($alg !== Minisign::ALG_SCRYPT) {
            throw new MinisignCryptoException('Invalid KDF algorithm');
        }
        return \sodium_crypto_pwhash_scryptsalsa208sha256(104, $pw, $salt, $ops, $mem);
    }

    /**
     * @return string
     */
    public function getKeyId(): string
    {
        return $this->keyId;
    }

    /**
     * @return string
     */
    public function getSecretKeyString(): string
    {
        return $this->ed25519sk;
    }

    /**
     * @return PublicKey
     * @throws MinisignException
     */
    public function getPublicKey(): PublicKey
    {
        return PublicKey::fromBase64String(
            Base64::encode($this->ed25519pk),
            $this->keyId
        );
    }

    /**
     * @return string
     */
    public function getPublicKeyString(): string
    {
        return $this->ed25519pk;
    }

    /**
     * Serialize this secret key for file storage.
     *
     * @param string $password
     * @return string
     * @throws \SodiumException
     * @throws MinisignException
     * @throws \Exception
     */
    public function serialize(string $password): string
    {
        $output = Minisign::COMMENT_PREFIX . $this->untrustedComment . "\r\n";

        $toEncode = $this->signatureAlgorithm . $this->kdfAlgorithm . $this->checksumAlgorithm;
        $kdfSalt = \random_bytes(32);
        $toEncode .= $kdfSalt;
        $toEncode .= \pack('V', $this->kdfOpsLimit) . "\0\0\0\0";
        $toEncode .= \pack('V', $this->kdfMemLimit) . "\0\0\0\0";
        $kdfOutput = self::kdf($this->kdfAlgorithm, $password, $kdfSalt, $this->kdfOpsLimit, $this->kdfMemLimit);
        \sodium_memzero($password);
        $checksum = \sodium_crypto_generichash(
            $this->signatureAlgorithm . $this->keyId . $this->ed25519sk
        );
        $toXor = $this->keyId . $this->ed25519sk . $checksum;
        $toEncode .= $kdfOutput ^ $toXor;
        return $output . Base64::encode($toEncode) . "\r\n";
    }

    /**
     * Return a copy of this object with a different checksum algorithm.
     *
     * @param string $alg
     * @return self
     */
    public function withChecksumAlgorithm(string $alg): self
    {
        $self = clone $this;
        $self->checksumAlgorithm = $alg;
        return $self;
    }

    /**
     * Return a copy of this object with a different KDF algorithm.
     *
     * @param string $alg
     * @return self
     */
    public function withKdfAlgorithm(string $alg): self
    {
        $self = clone $this;
        $self->kdfAlgorithm = $alg;
        return $self;
    }

    /**
     * Return a copy of this object with a limited KDF memory.
     *
     * @param int $memLimit
     * @return self
     */
    public function withKdfMemLimit(int $memLimit): self
    {
        $self = clone $this;
        $self->kdfMemLimit = $memLimit;
        return $self;
    }

    /**
     * Return a copy of this object with a limited number of KDF ops.
     *
     * @param int $opsLimit
     * @return self
     */
    public function withKdfOpsLimit(int $opsLimit): self
    {
        $self = clone $this;
        $self->kdfOpsLimit = $opsLimit;
        return $self;
    }

    /**
     * Return a copy of this object with the provided key ID.
     *
     * @param string $keyId
     * @return self
     * @throws MinisignException
     */
    public function withKeyId(string $keyId): self
    {
        if (Binary::safeStrlen($keyId) !== 8) {
            throw new MinisignException('Invalid Key ID; must be 8 bytes.');
        }
        $self = clone $this;
        $self->keyId = $keyId;
        return $self;
    }

    /**
     * Return a copy of this object with a different signature algorithm.
     *
     * @param string $alg
     * @return self
     */
    public function withSignatureAlgorithm(string $alg): self
    {
        $self = clone $this;
        $self->signatureAlgorithm = $alg;
        return $self;
    }

    /**
     * Return a copy of this object with the untrusted comment for when this key is serialized
     * set to whatever the user provided.
     *
     * @param string $comment
     * @return self
     */
    public function withUntrustedComment(string $comment): self
    {
        $self = clone $this;
        $self->untrustedComment = $comment;
        return $self;
    }
}
