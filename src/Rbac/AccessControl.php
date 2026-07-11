<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Rbac;

/**
 * Role-based access control.
 *
 * Roles map to sets of permissions. A user may have many roles. Guards
 * check whether a user's roles grant a given permission.
 *
 * Supports wildcard patterns: "content.*" matches "content.create", etc.
 */
class AccessControl
{
    /**
     * @var array<string, string[]> role => permissions
     */
    private array $roles = [];

    /**
     * Define a role and the permissions it grants.
     *
     * @param string[] $permissions
     */
    public function defineRole(string $role, array $permissions): void
    {
        $this->roles[$role] = $permissions;
    }

    /**
     * Load roles from a config array.
     *
     * @param array<string, string[]> $roles role => permissions
     */
    public function loadRoles(array $roles): void
    {
        $this->roles = array_merge($this->roles, $roles);
    }

    /**
     * Return all permissions granted to a set of roles.
     *
     * @return string[]
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
     *
     * Supports wildcards: "content.*" matches "content.create".
     */
    public function can(array $userRoles, string $permission): bool
    {
        $granted = $this->permissionsFor($userRoles);

        foreach ($granted as $pattern) {
            if ($this->matchesPattern($pattern, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if any of the given permissions are granted.
     *
     * @param string[] $permissions
     */
    public function canAny(array $userRoles, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->can($userRoles, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if all of the given permissions are granted.
     *
     * @param string[] $permissions
     */
    public function canAll(array $userRoles, array $permissions): bool
    {
        foreach ($permissions as $permission) {
            if (!$this->can($userRoles, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get all defined roles.
     *
     * @return array<string, string[]>
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * Get the role for an email.
     */
    public function role(string $email): string
    {
        return $this->roles[strtolower(trim($email))] ?? 'editor';
    }

    /**
     * Check if a pattern matches a permission.
     *
     * "content.*" matches "content.create"
     * "content.*" matches "content.edit"
     * "*" matches everything
     */
    private function matchesPattern(string $pattern, string $permission): bool
    {
        if ($pattern === '*') {
            return true;
        }

        $prefix = rtrim($pattern, '*');

        return str_starts_with($permission, $prefix);
    }
}
