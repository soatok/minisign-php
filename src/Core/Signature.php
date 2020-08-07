<?php
declare(strict_types=1);
namespace Soatok\Minisign\Core;

use Soatok\Minisign\Core\File\SigFile;
use Soatok\Minisign\Exceptions\MinisignException;
use Soatok\Minisign\Minisign;

/**
 * Class Signature
 * @package Soatok\Minisign\Core
 */
class Signature
{
    /** @var string $alg */
    private $alg;

    /** @var string $globalSignature */
    private $globalSignature;

    /** @var string $keyId */
    private $keyId;

    /** @var string $signature */
    private $signature;

    /** @var string $trustedComment */
    private $trustedComment;

    /** @var string $untrustedComment */
    private $untrustedComment;

    /**
     * Signature constructor.
     *
     * @param string $signature
     * @param string $keyId
     * @param string $globalSignature
     * @param string $alg
     * @param string $trustedComment
     * @param string $untrustedComment
     */
    public function __construct(
        string $signature,
        string $keyId,
        string $globalSignature,
        string $alg = Minisign::ALG_EDDSA,
        string $trustedComment = '',
        string $untrustedComment = ''
    ) {
        $this->alg = $alg;
        $this->globalSignature = $globalSignature;
        $this->keyId = $keyId;
        $this->signature = $signature;
        $this->trustedComment = $trustedComment;
        $this->untrustedComment = $untrustedComment;
    }

    /**
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->alg;
    }

    /**
     * @return string
     */
    public function getKeyId(): string
    {
        return $this->getKeyId();
    }

    /**
     * @return bool
     */
    public function isPreHashed(): bool
    {
        return \hash_equals($this->alg, Minisign::ALG_HASHEDDSA);
    }

    /**
     * @return string
     */
    public function getGlobalSignature(): string
    {
        return $this->globalSignature;
    }

    /**
     * @return string
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * @return string
     */
    public function getTrustedComment(): string
    {
        return $this->trustedComment;
    }

    /**
     * @return string
     */
    public function getUntrustedComment(): string
    {
        return $this->untrustedComment;
    }

    /**
     * @return SigFile
     * @throws MinisignException
     */
    public function toSigFile(): SigFile
    {
        return SigFile::serialize($this);
    }

    /**
     * @param SigFile $file
     * @return Signature
     * @throws MinisignException
     */
    public static function deserialize(SigFile $file): Signature
    {
        return $file->deserialize();
    }
}
