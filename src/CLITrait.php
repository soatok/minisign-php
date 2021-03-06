<?php
declare(strict_types=1);
namespace Soatok\Minisign;

use ParagonIE\ConstantTime\Binary;
use Soatok\Minisign\Exceptions\{
    MinisignException,
    MinisignFileException
};

/**
 * Trait CLITrait
 * @package Soatok\Minisign
 */
trait CLITrait
{
    /**
     * Prompt the user for an input value
     *
     * @param string $text
     * @return string
     */
    public function prompt($text): string
    {
        $fp = \fopen('php://stdin', 'r');
        echo $text;
        return Binary::safeSubstr(\fgets($fp), 0, -1);
    }

    /**
     * Interactively prompts for input without echoing to the terminal.
     * Requires a bash shell or Windows and won't work with
     * safe_mode settings (Uses `shell_exec`)
     *
     * @ref http://www.sitepoint.com/interactive-cli-password-prompt-in-php/
     *
     * @param string $text
     * @return string
     *
     * @throws MinisignException
     */
    public function silentPrompt(string $text = 'Enter Password:'): string
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $password = $this->silentPromptWindows($text);
        } elseif (defined('STDIN')) {
            echo $text, ' ';
            $password = $this->silentPromptStdin();
            echo PHP_EOL;
        } else {
            throw new MinisignException('STDIN not defined');
        }
        return $password;
    }

    /**
     * Prompt the user with a popup to provide the requested information.
     *
     * @param string $text
     * @return string
     * @psalm-suppress ForbiddenCode { THIS IS FINE }
     */
    protected function silentPromptWindows(string $text): string
    {
        $vbscript = \sys_get_temp_dir() . 'prompt_password.vbs';
        \file_put_contents(
            $vbscript,
            'wscript.echo(InputBox("' . \addslashes($text) . '", "", "password here"))'
        );
        $command = "cscript //nologo " . \escapeshellarg($vbscript);
        $password = \rtrim((string) \shell_exec($command));
        \unlink($vbscript);
        return $password;
    }

    /**
     * Read input from STDIN without echoing it to the shell.
     *
     * @return string
     * @throws MinisignFileException
     * @psalm-suppress ForbiddenCode { THIS IS FINE }
     */
    protected function silentPromptStdin(): string
    {
        if (!defined('STDIN')) {
            throw new MinisignFileException('STDIN is not available');
        }
        \exec('stty -echo');
        $result = \fgets(STDIN);
        \exec('stty echo');
        return $result;
    }
}
