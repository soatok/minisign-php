<?php
declare(strict_types=1);
namespace Soatok\Minisign\Tests\File;

use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Core\File\MessageFile;
use Soatok\Minisign\Core\SecretKey;
use Soatok\Minisign\Exceptions\MinisignException;

/**
 * Class MessageFileTest
 * @package Soatok\Minisign\Tests\File
 */
class MessageFileTest extends TestCase
{
    /** @var string $random */
    private $random;

    /** @var string $hash */
    private $hash;

    /**
     * @throws \Exception
     * @throws \SodiumException
     */
    public function setUp(): void
    {
        parent::setUp();
        $this->random = \random_bytes(786433);
        $this->hash = \sodium_crypto_generichash($this->random, '', 64);
    }
    /**
     * @throws MinisignException
     * @throws \SodiumException
     */
    public function testSignVerify()
    {
        $fp = \fopen('php://temp', 'wb');
        \fwrite($fp, $this->random);
        \fseek($fp, 0);
        $messageFile = MessageFile::fromStream($fp);
        if (!($messageFile instanceof MessageFile)) {
            $this->fail('Message File is not the right type');
        }
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $signature = $messageFile->sign($sk, false, 'Dreamseeker', 'Soatok');
        $this->assertTrue(
            $messageFile->verify($pk, $signature),
            'Signature that was just generated does not pass'
        );
        $sigPrehash = $messageFile->sign($sk, true, 'Dreamseeker', 'Soatok');
        $this->assertTrue(
            $messageFile->verify($pk, $sigPrehash),
            'Signature that was just generated does not pass (prehashed)'
        );
        $this->assertNotSame(
            $signature->getSignature(),
            $sigPrehash->getSignature()
        );
    }
}
