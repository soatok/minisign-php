<?php
namespace Soatok\Minisign\Tests\Commands;

use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Commands\Sign;
use Soatok\Minisign\Exceptions\MinisignException;

/**
 * Class SignTest
 * @package Soatok\Minisign\Tests\Commands
 */
class SignTest extends TestCase
{
    /**
     * @throws MinisignException
     */
    public function testFileFlattening()
    {
        $sign = new Sign([
            'm' => [__DIR__ . '/SignTest.php']
        ], [
            __DIR__ . '/SignTest.php'
        ]);
        $files = $sign->getFiles();
        $this->assertSame(1, \count($files));
    }

    /**
     * @throws MinisignException
     */
    public function testFileExpanding()
    {
        $sign = new Sign([
            'm' => [__DIR__ . '/*.php']
        ]);
        $files = $sign->getFiles();
        $this->assertSame(3, \count($files));
    }
}
