<?php
declare(strict_types=1);
namespace Soatok\Minisign\Core;

use phpDocumentor\Reflection\Types\Static_;
use Soatok\Minisign\Exceptions\MinisignFileException;

/**
 * Class FileStream
 *
 * Copies a file into memory to prevent filesystem-accessible race conditions.
 *
 * @package Soatok\Minisign
 */
class FileStream
{
    /** @var int $chunkSize */
    protected $chunkSize = 8192;

    /** @var resource $fp */
    private $fp;

    /** @var int $fp */
    private $pos = 0;

    /** @var array<array-key, mixed> $stat */
    private $stat;

    /**
     * FileStream constructor.
     * @param resource $fp
     * @throws MinisignFileException
     * @throws \TypeError
     */
    public function __construct($fp)
    {
        if (!\is_resource($fp)) {
            throw new \TypeError('Argument 1 must be a resource, ' . \gettype($fp) . ' given.');
        }
        $this->fp = $fp;
        $pos = \ftell($this->fp);
        if (!\is_int($pos)) {
            throw new MinisignFileException('Could not get current stream position');
        }
        $this->pos = $pos;
        $stat = \fstat($this->fp);
        if (!\is_array($stat)) {
            throw new MinisignFileException('fstat() returned invalid data');
        }
        $this->stat = $stat;
    }

    /**
     * Ensure file handle is closed on destruction.
     */
    public function __destruct()
    {
        \fclose($this->fp);
    }

    /**
     * Copy the stream into a temporary buffer, return a new instance of
     * FileStream.
     *
     * @param resource $resource
     * @return static
     * @throws MinisignFileException
     * @throws \TypeError
     */
    public static function fromStream($resource): self
    {
        if (!\is_resource($resource)) {
            throw new \TypeError('Argument 1 must be a resource, ' . \gettype($resource) . ' given.');
        }
        \fseek($resource, 0);
        $fp = \fopen('php://temp', 'wb');
        $result = \stream_copy_to_stream($resource, $fp);
        if (!\is_int($result)) {
            throw new MinisignFileException('Could not copy stream to temporary buffer');
        }
        return new static($fp);
    }

    /**
     * @param string $path
     * @return static
     * @throws MinisignFileException
     */
    public static function fromFile(string $path): self
    {
        $fp = \fopen(\realpath($path), 'rb');
        if (!\is_resource($fp)) {
            throw new MinisignFileException('Could not open file for reading');
        }
        try {
            return self::fromStream($fp);
        } finally {
            // Close dangling file pointer after we've copied file to internal stream
            \fclose($fp);
        }
    }

    /**
     * @return string
     */
    public function getContents(): string
    {
        \fseek($this->fp, 0, SEEK_SET);
        return (string) \stream_get_contents($this->fp);
    }

    /**
     * Get the file's hash.
     *
     * @return string
     * @throws \SodiumException
     */
    public function hash(): string
    {
        $pos = \ftell($this->fp);
        \fseek($this->fp, 0);
        $state = \sodium_crypto_generichash_init('', SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        do {
            /** @var string|bool $chunk */
            $chunk = \fread($this->fp, $this->chunkSize);
            if (\is_string($chunk)) {
                \sodium_crypto_generichash_update($state, $chunk);
            }
        } while (!\feof($this->fp));
        \fseek($this->fp, $pos);
        return \sodium_crypto_generichash_final($state, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
    }

    /**
     * @param int $chunkSize
     * @return self
     *
     * @psalm-suppress UnusedFunctionCall
     */
    public function setChunkSize(int $chunkSize = 8192): self
    {
        $this->chunkSize = $chunkSize;
        \stream_set_chunk_size($this->fp, $this->chunkSize);
        return $this;
    }
}
