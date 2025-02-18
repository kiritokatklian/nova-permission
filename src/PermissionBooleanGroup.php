<?php

namespace Vyuldashev\NovaPermission;

use Auth;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use Laravel\Nova\Fields\BooleanGroup;
use Laravel\Nova\Http\Requests\NovaRequest;
use Spatie\Permission\Models\Permission as PermissionModel;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\HasPermissions;
use Stringable;

class PermissionBooleanGroup extends BooleanGroup
{
    /**
     * Create a new field.
     *
     * @param Stringable|string                             $name
     * @param string|callable|object|null                    $attribute
     * @param (callable(mixed, mixed, ?string):(mixed))|null $resolveCallback
     * @param string|null                                    $labelAttribute
     *
     * @return void
     */
    public function __construct($name, mixed $attribute = null, ?callable $resolveCallback = null, ?string $labelAttribute = null)
    {
        parent::__construct(
            $name,
            $attribute,
            $resolveCallback ?? static function (?Collection $permissions) {
                return ($permissions ?? collect())->mapWithKeys(function (PermissionModel $permission) {
                    return [$permission->name => true];
                });
            }
        );

        $permissionClass = app(PermissionRegistrar::class)->getPermissionClass();

        $options = $permissionClass::all()->filter(function ($permission) {
            return Auth::user()->can('view', $permission);
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
        if (!in_array(HasPermissions::class, class_uses_recursive($model))) {
            throw new InvalidArgumentException('The $model parameter of type ' . $model::class . ' must implement ' . HasPermissions::class);
        }

        if (!$request->exists($requestAttribute)) {
            return;
        }

        $values = collect(json_decode($request[$requestAttribute], true))
            ->filter(static function (bool $value) {
                return $value;
            })
            ->keys()
            ->toArray();

        $model->syncPermissions($values);
    }
}
