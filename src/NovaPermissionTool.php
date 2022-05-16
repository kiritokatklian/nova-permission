<?php

namespace Vyuldashev\NovaPermission;

use Gate;
use Laravel\Nova\Nova;
use Laravel\Nova\Tool;
use Illuminate\Http\Request;
use Laravel\Nova\Menu\MenuSection;

class NovaPermissionTool extends Tool
{
    public string $roleResource = Role::class;
    public string $permissionResource = Permission::class;

    public string $rolePolicy = RolePolicy::class;
    public string $permissionPolicy = PermissionPolicy::class;

    /**
     * Perform any tasks that need to happen when the tool is booted.
     *
     * @return void
     */
    public function boot()
    {
        Nova::resources([
            $this->roleResource,
            $this->permissionResource,
        ]);

        Gate::policy(config('permission.models.permission'), $this->permissionPolicy);
        Gate::policy(config('permission.models.role'), $this->rolePolicy);
    }

    public function roleResource(string $roleResource): NovaPermissionTool
    {
        $this->roleResource = $roleResource;

        return $this;
    }

    public function permissionResource(string $permissionResource): NovaPermissionTool
    {
        $this->permissionResource = $permissionResource;

        return $this;
    }

    public function rolePolicy(string $rolePolicy): NovaPermissionTool
    {
        $this->rolePolicy = $rolePolicy;

        return $this;
    }

    public function permissionPolicy(string $permissionPolicy)
    {
        $this->permissionPolicy = $permissionPolicy;

        return $this;
    }
    
    // This is an abstract method in nova Tool class, so we MUST implement it.
    public function menu(Request $request)
    {
        return $this;
    }
}
