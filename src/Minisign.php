<?php
declare(strict_types=1);
namespace Soatok\Minisign;

/**
 * Class Minisign
 * @package Soatok\Minisign
 */
class Minisign
{
    const VERSION_STRING = 'minisign 0.9'; // What we aim to be compatible with!
    const ALG_EDDSA = 'Ed';
    const ALG_HASHEDDSA = 'ED';
    const ALG_SCRYPT = 'Sc';
    const ALG_BLAKE2 = 'B2';
    const REGEX = '#^' . Minisign::COMMENT_PREFIX . '(.+?)[\r\n\s]+([A-Za-z0-9+/=]+)[\s]+?$#';
    const COMMENT_PREFIX = 'untrusted comment: ';
    const TRUSTED_COMMENT_PREFIX = 'trusted comment: ';

    /**
     * Get the homedir of the current active user.
     *
     * @return string
     */
    public static function getHomeDir(): string
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            // Windows-specific:
            return (string) $_SERVER['HOMEDRIVE'] . (string) $_SERVER['HOMEPATH'];
        }
        // Linux and Mac:
        return (string) $_SERVER['HOME'];
    }
}
