<?php
declare(strict_types=1);
namespace Soatok\Minisign\Commands;

use Soatok\Minisign\CLITrait;
use Soatok\Minisign\CommandInterface;
use Soatok\Minisign\Core\File\MessageFile;
use Soatok\Minisign\Core\SecretKey;
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

    /** @var string $file */
    private $file;

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
     * @throws MinisignException
     */
    public function __construct(array $options)
    {
        if (empty($options['m'])) {
            throw new MinisignException('Error: file not specified');
        }
        $this->file = \realpath((string) $options['m']);

        if (!empty($options['x'])) {
            $this->sigFile = (string) $options['x'];
        } else {
            $this->sigFile = $this->file . '.minisig';
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
        $message = MessageFile::fromFile($this->file);
        $password = $this->silentPrompt();
        $sk = SecretKey::fromFile($this->secretKeyFile, $password);
        $sig = $message->sign($sk, $this->preHash, $this->trustedComment, $this->untrustedComment);
        \file_put_contents(
            $this->sigFile,
            $sig->toSigFile()->getContents()
        );
    }
}
