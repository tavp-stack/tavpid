<?php

declare(strict_types=1);

namespace Tavp\Tavpid\Tests;

use Tavp\Tavpid\Auth\AuthService;
use Tavp\Tavpid\Auth\OtpService;
use Tavp\Tavpid\Auth\TokenService;
use Tavp\Tavpid\Auth\UserProvider;
use Tavp\Tavpid\Rbac\AccessControl;
use PHPUnit\Framework\TestCase;

/**
 * In-memory user provider for testing TAVPid without a database.
 */
class ArrayUserProvider implements UserProvider
{
    private array $users = [];
    private int $nextId = 1;

    public function findByIdentifier(string $identifier): ?object
    {
        foreach ($this->users as $user) {
            if ($user->email === $identifier) {
                return $user;
            }
        }

        return null;
    }

    public function findById(int $id): ?object
    {
        return $this->users[$id] ?? null;
    }

    public function create(string $identifier): object
    {
        $user = (object) ['id' => $this->nextId, 'email' => $identifier];
        $this->users[$this->nextId] = $user;
        $this->nextId++;

        return $user;
    }
}

class AuthTest extends TestCase
{
    public function testOtpHashAndVerify(): void
    {
        $otp = new OtpService();
        $code = $otp->createOtp('user@example.com');
        $hash = $otp->hash($code);
        $this->assertTrue($otp->verifyOtp($code, $hash));
        $this->assertFalse($otp->verifyOtp('000000', $hash));
    }

    public function testFullLoginFlow(): void
    {
        $otp = new OtpService();
        $tokens = new TokenService('secret');
        $users = new ArrayUserProvider();
        $auth = new AuthService($otp, $tokens, $users);

        $code = $otp->createOtp('user@example.com');
        $hash = $otp->hash($code);

        $result = $auth->verifyOtpAndLogin('user@example.com', $code, $hash);
        $this->assertNotNull($result);
        $this->assertArrayHasKey('access_token', $result);

        $user = $auth->currentUser($result['access_token']);
        $this->assertSame('user@example.com', $user->email);
    }

    public function testRbacGrantsAndDenies(): void
    {
        $acl = new AccessControl();
        $acl->defineRole('admin', ['users.view', 'users.delete']);
        $acl->defineRole('editor', ['users.view']);

        $this->assertTrue($acl->can(['admin'], 'users.delete'));
        $this->assertFalse($acl->can(['editor'], 'users.delete'));
        $this->assertTrue($acl->can(['editor', 'admin'], 'users.view'));
    }
}
