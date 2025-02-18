<?php

namespace Vyuldashev\NovaPermission;

use Auth;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use Laravel\Nova\Fields\BooleanGroup;
use Laravel\Nova\Http\Requests\NovaRequest;
use Spatie\Permission\Models\Role as RoleModel;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\HasRoles;
use Stringable;

class RoleBooleanGroup extends BooleanGroup
{
    /**
     * Create a new field.
     *
     * @param Stringable|string                              $name
     * @param string|callable|object|null                    $attribute
     * @param null|(callable(mixed, mixed, ?string):(mixed)) $resolveCallback
     * @param null|string                                    $labelAttribute
     *
     * @return void
     */
    public function __construct($name, mixed $attribute = null, ?callable $resolveCallback = null, ?string $labelAttribute = null)
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

        $options = $roleClass::all()->filter(function ($role) {
            return Auth::user()->can('view', $role);
        })->pluck($labelAttribute ?? 'name', 'name');

        $this->options($options);
    }

    /**
     * @param NovaRequest $request
     * @param string      $requestAttribute
     * @param object      $model
     * @param string      $attribute
     *
     * @return void
     */
    protected function fillAttributeFromRequest(NovaRequest $request, string $requestAttribute, object $model, string $attribute): void
    {
        if (!in_array(HasRoles::class, class_uses_recursive($model))) {
            throw new InvalidArgumentException('The $model parameter of type ' . $model::class . ' must implement ' . HasRoles::class);
        }

        if (!$request->exists($requestAttribute)) {
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
