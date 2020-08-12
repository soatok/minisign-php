<?php
declare(strict_types=1);
namespace Soatok\Minisign\Commands;

use Soatok\Minisign\CommandInterface;
use Soatok\Minisign\Core\File\{
    MessageFile,
    SigFile
};
use Soatok\Minisign\Core\PublicKey;
use Soatok\Minisign\Exceptions\{
    MinisignException,
    MinisignFileException
};

/**
 * Class Verify
 * @package Soatok\MiniVerify\Commands
 */
class Verify implements CommandInterface
{
    /** @var PublicKey $publicKey */
    private $publicKey;

    /** @var string $file */
    private $file;

    /** @var string $sigFile */
    private $sigFile;

    /** @var bool $output */
    private $output = false;

    /** @var int $quiet */
    private $quiet;

    /**
     * Verify constructor.
     * @param array $options
     * @throws MinisignException
     */
    public function __construct(array $options)
    {
        if (!empty($options['P'])) {
            $this->publicKey = PublicKey::fromBase64String((string) $options['P']);
        } elseif (!empty($options['p'])) {
            $this->publicKey = PublicKey::fromFile((string) $options['p']);
        } else {
            $this->publicKey = PublicKey::fromFile(\getcwd() . '/minisign.pub');
        }

        if (empty($options['m'])) {
            throw new MinisignException('Error: file not specified');
        }
        /** @var array<array-key, string> $files */
        $files = $options['m'];
        $file = (string) $files[0];
        $realpath = \realpath($file);
        if (empty($realpath)) {
            throw new MinisignFileException('File not found: ' . $file);
        }
        $this->file = $realpath;

        if (!empty($options['x'])) {
            $this->sigFile = (string) $options['x'];
        } else {
            $this->sigFile = $this->file . '.minisig';
        }
        $this->output = !empty($options['o']);

        if (!empty($options['q'])) {
            $this->quiet = 2;
        } elseif (!empty($options['Q'])) {
            $this->quiet = 1;
        } else {
            $this->quiet = 0;
        }
    }

    /**
     * @return string
     */
    public function getFile(): string
    {
        return $this->file;
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * @return int
     */
    public function getQuietLevel(): int
    {
        return $this->quiet;
    }

    /**
     * @return string
     */
    public function getSignatureFile(): string
    {
        return $this->sigFile;
    }

    /**
     * @return void
     * @throws MinisignException
     */
    public function __invoke()
    {
        $message = MessageFile::fromFile($this->file);
        $sigFile = SigFile::fromFile($this->sigFile);
        $signature = $sigFile->deserialize();
        $message->verify(
            $this->publicKey,
            $signature
        );
        switch ($this->quiet) {
            case 2:
                break;
            case 1:
                echo $signature->getTrustedComment(), PHP_EOL;
                break;
            default:
                echo 'Signature and comment signature verified', PHP_EOL;
                echo 'Trusted comment: ', $signature->getTrustedComment(), PHP_EOL;
        }
        if ($this->output) {
            echo $message->getContents();
        }
    }
}
