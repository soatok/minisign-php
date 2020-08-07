<?php
declare(strict_types=1);
namespace Soatok\Minisign\Tests;

use ParagonIE\ConstantTime\Base64;
use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Exceptions\MinisignException;
use Soatok\Minisign\Core\SecretKey;

/**
 * Class SecretKeyTest
 * @package Soatok\Minisign\Tests
 */
class SecretKeyTest extends TestCase
{
    public function testSerialization()
    {
        $sk = SecretKey::generate()
            ->withKdfMemLimit(SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE)
            ->withKdfOpsLimit(SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE);
        $password = 'correct horse battery staple';
        $serialized = $sk->serialize($password);
        $deser = SecretKey::deserialize($serialized, $password);

        $this->assertSame(
            $sk->getKeyId(),
            $deser->getKeyId()
        );

        $this->assertSame(
            bin2hex($sk->getSecretKeyString()),
            bin2hex($deser->getSecretKeyString())
        );
        $this->assertSame(
            bin2hex($sk->getPublicKeyString()),
            bin2hex($deser->getPublicKeyString())
        );

        $failed = false;
        try {
            SecretKey::deserialize($serialized, 'incorrect');
        } catch (MinisignException $ex) {
            $failed = true;
        }
        $this->assertTrue($failed, 'Incorrect password did not fail');
    }

    public function testFileLoading()
    {
        $password = 'correct horse battery staple';
        $filename = __DIR__ . '/data/secretkey.test';
        $sk = SecretKey::fromFile($filename, $password);
        $encoded = Base64::encode($sk->getPublicKeyString());
        $this->assertSame('jYHw0uWCJc1G8VS3JuPIXa6t6zh7vGBWX7qC5bbuHE8=', $encoded);
        $this->assertSame($sk->getPublicKey()->getKeyId(), $sk->getKeyId());
    }
}
