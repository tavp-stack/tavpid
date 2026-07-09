<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Auth;

/**
 * Contract for the user store, so TAVPid works with any persistence
 * layer (Phalcon, Eloquent, plain array in tests).
 */
interface UserProvider
{
    public function findByIdentifier(string $identifier): ?object;

    public function findById(int $id): ?object;

    public function create(string $identifier): object;
}
