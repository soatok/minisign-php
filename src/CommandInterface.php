<?php
declare(strict_types=1);
namespace Soatok\Minisign;

/**
 * Class CommandInterface
 * @package Soatok\Minisign
 */
interface CommandInterface
{
    /**
     * CommandInterface constructor.
     * @param array $options
     */
    public function __construct(array $options);

    /**
     * @return void
     */
    public function __invoke();
}
