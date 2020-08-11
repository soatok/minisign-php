<?php
declare(strict_types=1);
namespace Soatok\Minisign\Commands;

use Soatok\Minisign\CLITrait;
use Soatok\Minisign\CommandInterface;
use Soatok\Minisign\Core\SecretKey;
use Soatok\Minisign\Exceptions\MinisignException;
use Soatok\Minisign\Minisign;

/**
 * Class Generate
 * @package Soatok\Minisign\Commands
 */
class Generate implements CommandInterface
{
    use CLITrait;

    /** @var bool $force */
    private $force;

    /**
     * Generate constructor.
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->force = !empty($options['f']);
    }

    /**
     * @return void
     * @throws MinisignException
     * @throws \SodiumException
     */
    public function __invoke()
    {
        if (!\is_dir(Minisign::getHomeDir() . '/.minisign')) {
            \mkdir(Minisign::getHomeDir() . '/.minisign', 0700);
        }
        $path = Minisign::getHomeDir() . '/.minisign/minisign.key';
        if (\file_exists($path) && !$this->force) {
            echo 'File already exists. Use -f to force generate.', PHP_EOL;
            exit(1);
        }

        $secretKey = SecretKey::generate();
        do {
            $password = $this->silentPrompt();
            $password2 = $this->silentPrompt('Please re-enter password:');
            $matched = \hash_equals($password, $password2);
            if (!$matched) {
                echo 'Passwords do not match! Please try again.', PHP_EOL;
            }
        } while (!$matched);

        \file_put_contents($path, $secretKey->serialize($password));
        \sodium_memzero($password);
    }
}
