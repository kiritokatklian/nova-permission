<?php

namespace Vyuldashev\NovaPermission;

use Auth;
use Illuminate\Support\Collection;
use Laravel\Nova\Fields\BooleanGroup;
use Laravel\Nova\Http\Requests\NovaRequest;
use Spatie\Permission\Models\Permission as PermissionModel;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\HasPermissions;

class PermissionBooleanGroup extends BooleanGroup
{
    public function __construct($name, $attribute = null, callable $resolveCallback = null, $labelAttribute = null, $checkUserViewPermission=true)
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

        $options = $permissionClass::all();
        // only filter out permissions if requested (time consuming operation)
        if ($checkUserViewPermission) {
            $options = $options->filter(function ($permission) {
                return Auth::user()->can('view', $permission);
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

        $values = collect(json_decode($request[$requestAttribute], true))
            ->filter(static function (bool $value) {
                return $value;
            })
            ->keys()
            ->toArray();

        $model->syncPermissions($values);
    }
}
