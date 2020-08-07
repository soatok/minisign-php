<?php
declare(strict_types=1);
namespace Soatok\Minisign\Tests;

use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Core\FileStream;
use Soatok\Minisign\Exceptions\MinisignException;

/**
 * Class FileStreamTest
 * @package Soatok\Minisign\Tests
 */
class FileStreamTest extends TestCase
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
     * @throws \Exception
     * @throws MinisignException
     * @throws \SodiumException
     */
    public function testFileRead()
    {
        $random = \bin2hex(\random_bytes(16));
        $filename = __DIR__ . '/filestream-' . $random . '.txt';
        file_put_contents($filename, $this->random);
        $file = FileStream::fromFile($filename);
        $this->assertSame(
            bin2hex($this->hash),
            bin2hex($file->hash()),
            'Hash mismatch'
        );
        \unlink($filename);
    }
}
