<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Tests;

use PHPUnit\Framework\TestCase;
use Tavp\Tavpid\Rbac\AccessControl;

class AccessControlTest extends TestCase
{
    private AccessControl $rbac;

    protected function setUp(): void
    {
        $this->rbac = new AccessControl();
        $this->rbac->defineRole('admin', ['content.*', 'user.*', 'settings.*']);
        $this->rbac->defineRole('editor', ['content.create', 'content.edit', 'content.browse']);
        $this->rbac->defineRole('viewer', ['content.browse']);
    }

    public function testCanWithExactPermission(): void
    {
        $this->assertTrue($this->rbac->can(['editor'], 'content.create'));
        $this->assertTrue($this->rbac->can(['editor'], 'content.edit'));
        $this->assertTrue($this->rbac->can(['editor'], 'content.browse'));
    }

    public function testCanWithWildcardPermission(): void
    {
        $this->assertTrue($this->rbac->can(['admin'], 'content.create'));
        $this->assertTrue($this->rbac->can(['admin'], 'content.edit'));
        $this->assertTrue($this->rbac->can(['admin'], 'user.delete'));
        $this->assertTrue($this->rbac->can(['admin'], 'settings.update'));
    }

    public function testCanWithDeniedPermission(): void
    {
        $this->assertFalse($this->rbac->can(['viewer'], 'content.create'));
        $this->assertFalse($this->rbac->can(['viewer'], 'content.edit'));
        $this->assertFalse($this->rbac->can(['editor'], 'user.delete'));
    }

    public function testCanWithMultipleRoles(): void
    {
        $this->assertTrue($this->rbac->can(['viewer', 'editor'], 'content.create'));
    }

    public function testCanWithNoRoles(): void
    {
        $this->assertFalse($this->rbac->can([], 'content.browse'));
    }

    public function testCanAny(): void
    {
        $this->assertTrue($this->rbac->canAny(['viewer'], ['content.create', 'content.browse']));
        $this->assertFalse($this->rbac->canAny(['viewer'], ['content.create', 'content.delete']));
    }

    public function testCanAll(): void
    {
        $this->assertTrue($this->rbac->canAll(['editor'], ['content.create', 'content.edit']));
        $this->assertFalse($this->rbac->canAll(['editor'], ['content.create', 'user.delete']));
    }

    public function testPermissionsFor(): void
    {
        $perms = $this->rbac->permissionsFor(['editor']);

        $this->assertContains('content.create', $perms);
        $this->assertContains('content.edit', $perms);
        $this->assertContains('content.browse', $perms);
        $this->assertNotContains('user.delete', $perms);
    }

    public function testLoadRoles(): void
    {
        $this->rbac->loadRoles([
            'moderator' => ['content.delete', 'user.browse'],
        ]);

        $this->assertTrue($this->rbac->can(['moderator'], 'content.delete'));
        $this->assertTrue($this->rbac->can(['moderator'], 'user.browse'));
    }

    public function testGetRoles(): void
    {
        $roles = $this->rbac->getRoles();

        $this->assertArrayHasKey('admin', $roles);
        $this->assertArrayHasKey('editor', $roles);
        $this->assertArrayHasKey('viewer', $roles);
    }

    public function testWildcardStar(): void
    {
        $this->rbac->defineRole('superadmin', ['*']);

        $this->assertTrue($this->rbac->can(['superadmin'], 'anything.goes'));
    }
}
