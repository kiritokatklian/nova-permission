<?php

namespace Vyuldashev\NovaPermission;

use Auth;
use Illuminate\Support\Collection;
use Laravel\Nova\Fields\Select;
use Laravel\Nova\Http\Requests\NovaRequest;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\HasRoles;
use Stringable;

class RoleSelect extends Select
{
    /**
     * Create a new field.
     *
     * @param Stringable|string                              $name
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
            $resolveCallback ?? static function (?Collection $roles) {
                return optional(($roles ?? collect())->first())->name;
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
            throw new \InvalidArgumentException('The $model parameter of type ' . $model::class . ' must implement ' . HasRoles::class);
        }

        if (!$request->exists($requestAttribute)) {
            return;
        }

        $model->syncRoles([]);

        if (!is_null($request[$requestAttribute])) {
            $roleClass = app(PermissionRegistrar::class)->getRoleClass();
            $role = $roleClass::where('name', $request[$requestAttribute])->first();
            $model->assignRole($role);
        }
    }

    /**
     * Display values using their corresponding specified labels.
     *
     * @return $this
     */
    public function displayUsingLabels(): RoleSelect
    {
        return $this->displayUsing(function ($value) {
            return collect($this->meta['options'])
                ->where('value', optional($value->first())->name)
                ->first()['label'] ?? optional($value->first())->name;
        });
    }
}
