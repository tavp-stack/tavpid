<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Rbac;

/**
 * Role-based access control.
 *
 * Roles map to sets of permissions. A user may have many roles. Guards
 * check whether a user's roles grant a given permission.
 */
class AccessControl
{
    /**
     * @var array<string, string[]> role => permissions
     */
    private array $roles = [];

    /**
     * Define a role and the permissions it grants.
     */
    public function defineRole(string $role, array $permissions): void
    {
        $this->roles[$role] = $permissions;
    }

    /**
     * Return all permissions granted to a set of roles.
     */
    public function permissionsFor(array $userRoles): array
    {
        $permissions = [];
        foreach ($userRoles as $role) {
            $permissions = array_merge($permissions, $this->roles[$role] ?? []);
        }

        return array_values(array_unique($permissions));
    }

    /**
     * Whether the given roles grant a permission.
     */
    public function can(array $userRoles, string $permission): bool
    {
        return in_array($permission, $this->permissionsFor($userRoles), true);
    }
}
