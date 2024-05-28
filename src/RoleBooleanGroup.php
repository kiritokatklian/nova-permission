<?php

namespace Vyuldashev\NovaPermission;

use Auth;
use Illuminate\Support\Collection;
use Laravel\Nova\Fields\BooleanGroup;
use Laravel\Nova\Http\Requests\NovaRequest;
use Spatie\Permission\Models\Role as RoleModel;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\HasPermissions;

class RoleBooleanGroup extends BooleanGroup
{
    public function __construct($name, $attribute = null, callable $resolveCallback = null, $labelAttribute = null, $checkUserViewPermission=true)
    {
        parent::__construct(
            $name,
            $attribute,
            $resolveCallback ?? static function (?Collection $roles) {
                return ($roles ?? collect())->mapWithKeys(function (RoleModel $role) {
                    return [$role->name => true];
                });
            }
        );

        $roleClass = app(PermissionRegistrar::class)->getRoleClass();

        $options = $roleClass::all();
        // only filter out permissions if requested (time consuming operation)
        if ($checkUserViewPermission) {
            $options = $options->filter(function ($role) {
                return Auth::user()->can('view', $role);
            });
        }
        $options = $options->pluck($labelAttribute ?? 'name', 'name');

        $this->options($options);
    }

    /**
     * @param NovaRequest $request
     * @param string $requestAttribute
     * @param HasPermissions $model
     * @param string $attribute
     */
    protected function fillAttributeFromRequest(NovaRequest $request, $requestAttribute, $model, $attribute)
    {
        if (! $request->exists($requestAttribute)) {
            return;
        }

        $model->syncRoles([]);

        collect(json_decode($request[$requestAttribute], true))
            ->filter(static function (bool $value) {
                return $value;
            })
            ->keys()
            ->map(static function ($roleName) use ($model) {
                $roleClass = app(PermissionRegistrar::class)->getRoleClass();
                $role = $roleClass::where('name', $roleName)->first();
                $model->assignRole($role);

                return $roleName;
            });
    }
}
