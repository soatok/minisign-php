<?php
declare(strict_types=1);
namespace Soatok\Minisign\Commands;

use ParagonIE\ConstantTime\Base64;
use Soatok\Minisign\Core\SecretKey;
use Soatok\Minisign\Exceptions\MinisignException;
use Soatok\Minisign\{
    Minisign,
    CLITrait,
    CommandInterface
};

/**
 * Class Generate
 * @package Soatok\Minisign\Commands
 */
class Generate implements CommandInterface
{
    use CLITrait;

    /** @var bool $force */
    private $force;

    /** @var string $publicKeyFile */
    private $publicKeyFile;

    /** @var string $secretKeyFile */
    private $secretKeyFile;

    /**
     * Generate constructor.
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->force = !empty($options['f']);
        if (!empty($options['s'])) {
            $this->secretKeyFile = (string) $options['s'];
        } else {
            if (!\is_dir(Minisign::getHomeDir() . '/.minisign')) {
                \mkdir(Minisign::getHomeDir() . '/.minisign', 0700);
            }
            $this->secretKeyFile = Minisign::getHomeDir() . '/.minisign/minisign.key';
        }

        if (!empty($options['p'])) {
            $this->publicKeyFile = (string) $options['p'];
        } else {
            $this->publicKeyFile = \getcwd() . '/minisign.pub';
        }
    }

    /**
     * @return bool
     */
    public function getForce(): bool
    {
        return $this->force;
    }

    /**
     * @return string
     */
    public function getPublicKeyFile(): string
    {
        return $this->publicKeyFile;
    }

    /**
     * @return string
     */
    public function getSecretKeyFile(): string
    {
        return $this->secretKeyFile;
    }

    /**
     * @return void
     * @throws MinisignException
     * @throws \SodiumException
     */
    public function __invoke()
    {
        if (\file_exists($this->secretKeyFile) && !$this->force) {
            echo 'File already exists. Use -f to force generate.', PHP_EOL;
            exit(1);
        }

        $secretKey = SecretKey::generate();
        do {
            $password = $this->silentPrompt();
            $password2 = $this->silentPrompt('Password (one more time):');
            $matched = \hash_equals($password, $password2);
            if (!$matched) {
                echo 'Passwords do not match! Please try again.', PHP_EOL;
            }
        } while (!$matched);
        echo 'Deriving a key from the password in order to encrypt the secret key...', PHP_EOL;

        // Serialize and store the secret key:
        \file_put_contents($this->secretKeyFile, $secretKey->serialize($password));
        \sodium_memzero($password);

        // Serialize and store the public key:
        $publicKey = $secretKey->getPublicKey();
        \file_put_contents($this->publicKeyFile, $publicKey->serialize());

        echo "The secret key was saved as {$this->secretKeyFile} - Keep it secret!", PHP_EOL;
        echo "The public key was saved as {$this->publicKeyFile} - That one can be public.", PHP_EOL, PHP_EOL;
        echo "Files signed using this key pair can be verified with the following command:", PHP_EOL;
        echo "minisign -Vm <file> -P ", Base64::encode($publicKey->getPublicKey()), PHP_EOL;
    }
}
