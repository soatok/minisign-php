<?php
declare(strict_types=1);
namespace Soatok\Minisign\Tests\Commands;

use ParagonIE\ConstantTime\Base64;
use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Commands\Verify;
use Soatok\Minisign\Exceptions\MinisignException;

/**
 * Class VerifyTest
 * @package Soatok\Minisign\Tests\Commands
 */
class VerifyTest extends TestCase
{
    /**
     * @throws MinisignException
     */
    public function testVerifyOps()
    {
        // Test with a base64-encoded public key:
        $dir = \realpath(\dirname(__DIR__, 2) . '/bin');
        $verify = new Verify([
            'm' => [$dir . '/usage.txt'],
            'P' => '9Gxq9/iRbNZeDzpF4SOwgwqTUt4v3A8gsPO9LktyQRI='
        ]);
        $this->assertSame(0, $verify->getQuietLevel());
        $this->assertSame(
            $dir . DIRECTORY_SEPARATOR . 'usage.txt',
            $verify->getFile()
        );
        $this->assertSame(
            $dir . DIRECTORY_SEPARATOR . 'usage.txt.minisig',
            $verify->getSignatureFile()
        );
        $this->assertSame(
            '9Gxq9/iRbNZeDzpF4SOwgwqTUt4v3A8gsPO9LktyQRI=',
            Base64::encode($verify->getPublicKey()->getPublicKey())
        );

        // Test with a file (-p filepath):
        $verify = new Verify([
            'm' => [$dir . '/usage.txt'],
            'p' => \dirname(__DIR__) . '/data/minisign.pub'
        ]);
        $this->assertSame(
            '9Gxq9/iRbNZeDzpF4SOwgwqTUt4v3A8gsPO9LktyQRI=',
            Base64::encode($verify->getPublicKey()->getPublicKey())
        );
    }
}
