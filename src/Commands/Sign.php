<?php
declare(strict_types=1);
namespace Soatok\Minisign\Commands;

use Soatok\Minisign\CLITrait;
use Soatok\Minisign\CommandInterface;
use Soatok\Minisign\Core\File\MessageFile;
use Soatok\Minisign\Core\SecretKey;
use Soatok\Minisign\Core\Signature;
use Soatok\Minisign\Exceptions\MinisignException;
use Soatok\Minisign\Minisign;

/**
 * Class Sign
 * @package Soatok\Minisign\Commands
 */
class Sign implements CommandInterface
{
    use CLITrait;

    /** @var string $secretKeyFile */
    private $secretKeyFile;

    /** @var string[] $file */
    private $files = [];

    /** @var string $sigFile */
    private $sigFile;

    /** @var bool $preHash */
    private $preHash = false;

    /** @var string $trustedComment */
    private $trustedComment = '';

    /** @var string $untrustedComment */
    private $untrustedComment = '';

    /**
     * Sign constructor.
     * @param array $options
     * @param array $operands
     * @throws MinisignException
     */
    public function __construct(array $options, array $operands = [])
    {
        if (empty($options['m'])) {
            throw new MinisignException('Error: file not specified');
        }
        /** @var array<array-key, string> $selectedFiles */
        $selectedFiles = $options['m'];
        /** @var string $file */
        foreach ($selectedFiles as $file) {
            $this->expandFilePath($file);
        }
        if (!empty($operands)) {
            /** @var string $operand */
            foreach ($operands as $operand) {
                $this->expandFilePath($operand);
            }
        }

        if (!empty($options['x']) && count($this->files) === 1) {
            $this->sigFile = (string) $options['x'];
        } else {
            $this->sigFile = '';
        }

        if (!empty($options['s'])) {
            $this->secretKeyFile = (string) $options['s'];
        } else {
            $this->secretKeyFile = Minisign::getHomeDir() . '/.minisign/minisign.key';
        }

        $this->preHash = !empty($options['H']);

        if (!empty($options['c'])) {
            $this->untrustedComment = (string) $options['c'];
        }
        if (!empty($options['t'])) {
            $this->trustedComment = (string) $options['t'];
        }
    }

    /**
     * @return void
     * @throws MinisignException
     * @throws \SodiumException
     */
    public function __invoke()
    {
        if (!\file_exists($this->secretKeyFile)) {
            throw new MinisignException('Secret key file not found: ' . $this->secretKeyFile);
        }
        $password = $this->silentPrompt();
        $sk = SecretKey::fromFile($this->secretKeyFile, $password);
        foreach ($this->files as $file) {
            $message = MessageFile::fromFile($file);
            $sig = $message->sign($sk, $this->preHash, $this->trustedComment, $this->untrustedComment);
            if (!$this->saveSignFile($sig, $file)) {
                throw new MinisignException('Could not write signature for file ' . $file);
            }
        }
    }

    /**
     * @param string $input
     */
    protected function expandFilePath(string $input): void
    {
        foreach (\glob($input) as $file) {
            $realpath = \realpath($file);
            if (!\is_dir($realpath)) {
                $this->files [] = $realpath;
            }
        }
    }

    /**
     * Save the signature file.
     *
     * @param Signature $sig
     * @param string $file
     * @return bool
     * @throws MinisignException
     */
    protected function saveSignFile(Signature $sig, string $file): bool
    {
        if (!empty($this->sigFile)) {
            $result = \file_put_contents(
                $this->sigFile,
                $sig->toSigFile()->getContents()
            );
        } else {
            $result = \file_put_contents(
                $file . '.minisig',
                $sig->toSigFile()->getContents()
            );
        }
        return \is_int($result);
    }
}
