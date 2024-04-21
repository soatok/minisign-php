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
 * Class PublicKey
 * @package Soatok\Minisign\Core
 */
class PublicKey
{
    const REGEX = '#^' . Minisign::COMMENT_PREFIX . '(.+?)[\s]+([A-Za-z0-9+/=]+)?[\s]*$#';

    /** @var string $pk */
    private $pk;

    /** @var string $keyId */
    private $keyId;

    /** @var string $untrustedComment */
    private $untrustedComment;

    /**
     * PublicKey constructor.
     *
     * @param string $pk
     * @param string $keyId
     * @param string $untrustedComment
     * @throws MinisignException
     */
    public function __construct(string $pk, string $keyId, string $untrustedComment = '')
    {
        $len = Binary::safeStrlen($pk);
        if ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new MinisignCryptoException(
                'Public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' bytes, got ' . $len . ' bytes.'
            );
        }
        $this->keyId = $keyId;
        $this->pk = $pk;
        $this->untrustedComment = $untrustedComment;
    }

    /**
     * @param string $contents
     * @return self
     * @throws MinisignException
     */
    public static function deserialize(string $contents): self
    {
        if (!\preg_match(self::REGEX, $contents, $m)) {
            throw new MinisignException('Invalid public key format');
        }
        $decoded = Base64::decode($m[2]);
        $keyId = Binary::safeSubstr($decoded, 0, 8);
        $pk = Binary::safeSubstr($decoded, 8, 32);
        return new self($pk, $keyId, $m[1]);
    }


    /**
     * @param string $path
     * @return self
     * @throws MinisignException
     */
    public static function fromFile(string $path): self
    {
        if (!\is_readable($path)) {
            throw new MinisignFileException('Cannot read file: ' . \realpath($path));
        }
        $contents = \file_get_contents($path);
        if (!\is_string($contents)) {
            throw new MinisignFileException('Could not read file: '. \realpath($path));
        }
        return self::deserialize($contents);
    }

    /**
     * @param string $encoded
     * @param string $keyId
     * @return self
     * @throws MinisignException
     */
    public static function fromBase64String(string $encoded, string $keyId = ''): self
    {
        return new PublicKey(Base64::decode($encoded), $keyId);
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
    public function getPublicKey(): string
    {
        return $this->pk;
    }

    /**
     * @return string
     */
    public function serialize(): string
    {
        if (empty($this->keyId)) {
            $this->keyId = \str_repeat("\0", 8);
        }
        return Minisign::COMMENT_PREFIX . $this->untrustedComment . "\r\n" .
            Base64::encodeUnpadded('Ed' . $this->keyId . $this->pk);
    }
}
