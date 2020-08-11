<?php
declare(strict_types=1);
namespace Soatok\Minisign\Core\File;

use Soatok\Minisign\Core\{
    FileStream,
    PublicKey,
    SecretKey,
    Signature
};
use Soatok\Minisign\Minisign;

/**
 * Class MessageFile
 * @package Soatok\Minisign
 */
class MessageFile extends FileStream
{
    /**
     * Sign this file with a secret key.
     *
     * @param SecretKey $sk
     * @param bool $preHash
     * @param string $trustedComment
     * @param string $untrustedComment
     * @return Signature
     * @throws \SodiumException
     */
    public function sign(
        SecretKey $sk,
        bool $preHash = false,
        string $trustedComment = '',
        string $untrustedComment = ''
    ): Signature {
        if ($preHash) {
            $signature = \sodium_crypto_sign_detached($this->hash(), $sk->getSecretKeyString());
        } else {
            $signature = \sodium_crypto_sign_detached($this->getContents(), $sk->getSecretKeyString());
        }
        $globalSignature = \sodium_crypto_sign_detached($signature . $trustedComment, $sk->getSecretKeyString());
        return new Signature(
            $signature,
            $sk->getKeyId(),
            $globalSignature,
            $preHash ? Minisign::ALG_HASHEDDSA : Minisign::ALG_EDDSA,
            $trustedComment,
            $untrustedComment
        );
    }

    /**
     * Verify this file has a valid minisign signature for the given public key.
     *
     * @param PublicKey $pk
     * @param Signature $sig
     * @return bool
     */
    public function verify(PublicKey $pk, Signature $sig): bool
    {
        if ($sig->isPreHashed()) {
            $valid = \sodium_crypto_sign_verify_detached(
                $sig->getSignature(),
                $this->hash(),
                $pk->getPublicKey()
            );
        } else {
            $valid = \sodium_crypto_sign_verify_detached(
                $sig->getSignature(),
                $this->getContents(),
                $pk->getPublicKey()
            );
        }
        $globalValid = \sodium_crypto_sign_verify_detached(
            $sig->getGlobalSignature(),
            $sig->getSignature() . $sig->getTrustedComment(),
            $pk->getPublicKey()
        );
        return $valid && $globalValid;
    }
}
