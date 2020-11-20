<?php
declare(strict_types=1);
namespace Soatok\Minisign\Core\File;

use Soatok\Minisign\Core\{
    FileStream,
    Signature
};
use ParagonIE\ConstantTime\{
    Base64,
    Binary
};
use Soatok\Minisign\Exceptions\MinisignFileException;
use Soatok\Minisign\Minisign;

/**
 * Class SigFile
 * @package Soatok\Minisign\Core
 */
class SigFile extends FileStream
{
    const LINE1_REGEX = '#^' . Minisign::COMMENT_PREFIX . '(.*)$#';
    const BASE64_REGEX = '#^([A-Za-z0-9+/=]+)$#';
    const LINE3_REGEX = '#^' . Minisign::TRUSTED_COMMENT_PREFIX . '(.+?)$#';

    /**
     * @param string $path
     * @return bool
     */
    public function saveTo(string $path): bool
    {
        /** @var int|bool $written */
        $written = \file_put_contents($path, $this->getContents());
        return $written !== false;
    }

    /**
     * Convert the signature into a stream.
     *
     * @param Signature $sig
     * @return static
     * @throws MinisignFileException
     */
    public static function serialize(Signature $sig): self
    {
        $fp = \fopen('php://temp', 'wb');
        \fwrite($fp, Minisign::COMMENT_PREFIX . $sig->getUntrustedComment() . "\r\n");
        \fwrite($fp, Base64::encode($sig->getAlgorithm() . $sig->getKeyId() . $sig->getSignature()) . "\r\n");
        \fwrite($fp, Minisign::TRUSTED_COMMENT_PREFIX . $sig->getTrustedComment() . "\r\n");
        \fwrite($fp, Base64::encode($sig->getGlobalSignature()));
        try {
            return static::fromStream($fp);
        } finally {
            \fclose($fp);
        }
    }

    /**
     * Deserializes the current stream into a Signature object.
     *
     * @return Signature
     * @throws MinisignFileException
     */
    public function deserialize(): Signature
    {
        /** @var array<array-key, string> $contents */
        $contents = \preg_split('/[\r\n]+/', $this->getContents());
        if (count($contents) < 4) {
            throw new MinisignFileException('Error deserializing signature file: Insufficient line count');
        }
        if (!\preg_match(self::LINE1_REGEX, $contents[0], $m)) {
            throw new MinisignFileException('Error deserializing signature file on line 1');
        }
        $untrusted = $m[1];

        if (!\preg_match(self::BASE64_REGEX, $contents[1], $m)) {
            throw new MinisignFileException('Error deserializing signature file on line 2');
        }
        $decoded = Base64::decode($m[1]);
        $alg = Binary::safeSubstr($decoded, 0, 2);
        $keyId = Binary::safeSubstr($decoded, 2, 8);
        $signature = Binary::safeSubstr($decoded, 10);

        if (!\preg_match(self::LINE3_REGEX, $contents[2], $m)) {
            throw new MinisignFileException('Error deserializing signature file on line 3');
        }
        $trusted = $m[1];
        if (!\preg_match(self::BASE64_REGEX, $contents[3], $m)) {
            throw new MinisignFileException('Error deserializing signature file on line 4');
        }
        $globalSignature = Base64::decode($m[1]);
        return new Signature($signature, $keyId, $globalSignature, $alg, $trusted, $untrusted);
    }
}
