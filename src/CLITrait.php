<?php
declare(strict_types=1);
namespace Soatok\Minisign;

use ParagonIE\ConstantTime\Binary;
use Soatok\Minisign\Exceptions\MinisignException;

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
     * @psalm-suppress ForbiddenCode { THIS IS FINE }
     */
    public function silentPrompt(string $text = 'Enter Password:'): string
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $vbscript = sys_get_temp_dir() . 'prompt_password.vbs';
            \file_put_contents(
                $vbscript,
                'wscript.echo(InputBox("' . \addslashes($text) . '", "", "password here"))'
            );
            $command = "cscript //nologo " . \escapeshellarg($vbscript);
            $password = \rtrim(
                (string) \shell_exec($command)
            );
            \unlink($vbscript);
        } else {
            $command = "/usr/bin/env bash -c 'echo OK'";
            if (\rtrim((string) \shell_exec($command)) !== 'OK') {
                throw new MinisignException("Can't invoke bash");
            }
            $command = "/usr/bin/env bash -c 'read -s -p \"" . \addslashes($text) . "\" mypassword && echo \$mypassword'";
            $password = \rtrim((string) \shell_exec($command));
            echo "\n";
        }
        return $password;
    }
}
