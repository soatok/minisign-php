<?php
declare(strict_types=1);
namespace Soatok\Minisign\Tests;

use ParagonIE\ConstantTime\Base64;
use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Core\PublicKey;
use Soatok\Minisign\Exceptions\MinisignException;

/**
 * Class PublicKeyTest
 * @package Soatok\Minisign\Tests
 */
class PublicKeyTest extends TestCase
{
    /** @var string $keyId */
    protected $keyId;

    /** @var string $sk */
    protected $sk;

    /** @var string $pk */
    protected $pk;

    /**
     * @throws \Exception
     * @throws \SodiumException
     */
    public function setUp(): void
    {
        $keypair = \sodium_crypto_sign_keypair();
        $this->keyId = \random_bytes(8);
        $this->sk = \sodium_crypto_sign_secretkey($keypair);
        $this->pk = \sodium_crypto_sign_publickey($keypair);
    }

    /**
     * @throws MinisignException
     */
    public function testFromBase64()
    {
        $pk = PublicKey::fromBase64String(Base64::encode($this->pk));
        $this->assertSame(
            $pk->getPublicKey(),
            $this->pk,
            'Public key mistmatch'
        );
    }

    /**
     * @throws \Exception
     */
    public function testFromDummyFile()
    {
        $random = \bin2hex(\random_bytes(16));
        $filename = __DIR__ . '/test.' . $random . '.base64';

        $pk = new PublicKey($this->pk, $this->keyId,  'comment');
        file_put_contents($filename, $pk->serialize());

        $pk = PublicKey::fromFile($filename);
        $this->assertSame(
            $pk->getPublicKey(),
            $this->pk,
            'Public key mismatch'
        );
        \unlink($filename);
    }

    /**
     * @throws MinisignException
     */
    public function testFromFile()
    {
        $filename = __DIR__ . '/data/minisign.pub';
        $pk = PublicKey::fromFile($filename);
        $this->assertSame(
            '45644535c704df22',
            bin2hex($pk->getKeyId())
        );
        $this->assertSame(
            'f46c6af7f8916cd65e0f3a45e123b0830a9352de2fdc0f20b0f3bd2e4b724112',
            bin2hex($pk->getPublicKey())
        );
    }
}
