<?php
declare(strict_types=1);
namespace Soatok\Minisign\Tests\Commands;

use PHPUnit\Framework\TestCase;
use Soatok\Minisign\Commands\Generate;

/**
 * Class GenerateTest
 * @package Soatok\Minisign\Tests\Commands
 */
class GenerateTest extends TestCase
{
    public function testGenerateOps()
    {
        $gen = new Generate(['f' => 1, 's' => __DIR__ . '/secret.key', 'p' => __DIR__ . '/public.key']);
        $this->assertSame(true, $gen->getForce());
        $this->assertSame(__DIR__ . '/secret.key', $gen->getSecretKeyFile());
        $this->assertSame(__DIR__ . '/public.key', $gen->getPublicKeyFile());
        $gen = new Generate(['s' => __DIR__ . '/secret.key', 'p' => __DIR__ . '/public.key']);
        $this->assertSame(false, $gen->getForce());
    }
}
