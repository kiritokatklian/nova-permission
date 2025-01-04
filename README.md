# A Laravel Nova tool for Spatie's laravel-permission library

[![Latest Version on Packagist](https://img.shields.io/packagist/v/kiritokatklian/nova-permission.svg?style=flat-square)](https://packagist.org/packages/kiritokatklian/nova-permission)
[![Total Downloads](https://img.shields.io/packagist/dt/kiritokatklian/nova-permission.svg?style=flat-square)](https://packagist.org/packages/kiritokatklian/nova-permission)

![screenshot 1](https://raw.githubusercontent.com/kiritokatklian/nova-permission/master/docs/user-resource.png)

## Note

Credits to [vyuldashev](https://github.com/vyuldashev). Since the original package hasn't been updated for a while now and there's no sign from vyuldashev, I created this fork with all the latest changes. I use this mainly in my projects, but feel welcome to use it as well. PRs are also welcome.

## Version Compatibility

With the release of Nova 4.0, there are now two separate versions of Nova Permissions. Unfortuantly due to the nature of the update, the new one isn't backwards copmatible. So please choose your version accordingly.

| Laravel Nova | Nova Permission |
| :---: | :---: |
| 3.0 | 3.0 - 3.2.2 |
| 4.0 | 4.0 |
| 5.0 | 5.0 |

## Installation

You can install the package in to a Laravel project that uses [Nova](https://nova.laravel.com) via composer:

```bash
composer require kiritokatklian/nova-permission
```

Go through the [Installation](https://github.com/spatie/laravel-permission#installation) section in order to setup [laravel-permission](https://packagist.org/packages/spatie/laravel-permission).

Next up, you must register the tool with Nova. This is typically done in the `tools` method of the `NovaServiceProvider`.

```php
// in app/Providers/NovaServiceProvider.php

// ...

public function tools()
{
    return [
        // ...
        \Vyuldashev\NovaPermission\NovaPermissionTool::make(),
    ];
}
```

Next, add middleware to `config/nova.php`

```php
// in config/nova.php
'middleware' => [
    // ...
    \Vyuldashev\NovaPermission\ForgetCachedPermissions::class,
],
```

Finally, add `MorphToMany` fields to you `app/Nova/User` resource:

```php
// ...
use Laravel\Nova\Fields\MorphToMany;

public function fields(Request $request)
{
    return [
        // ...
        MorphToMany::make('Roles', 'roles', \Vyuldashev\NovaPermission\Role::class),
        MorphToMany::make('Permissions', 'permissions', \Vyuldashev\NovaPermission\Permission::class),
    ];
}
```

Or if you want to attach multiple permissions at once, use `RoleBooleanGroup` and `PermissionBooleanGroup` fields (requires at least Nova 2.6.0):

```php
// ...
use Vyuldashev\NovaPermission\PermissionBooleanGroup;
use Vyuldashev\NovaPermission\RoleBooleanGroup;

public function fields(Request $request)
{
    return [
        // ...
        RoleBooleanGroup::make('Roles'),
        PermissionBooleanGroup::make('Permissions'),
    ];
}
```

If your `User` could have a single role at any given time, you can use `RoleSelect` field. This field will render a standard select where you can pick a single role from.

```php
// ...
use Vyuldashev\NovaPermission\PermissionBooleanGroup;
use Vyuldashev\NovaPermission\RoleSelect;

public function fields(Request $request)
{
    return [
        // ...
        RoleSelect::make('Role', 'roles'),
    ];
}
```

## Customization

If you want to use custom resource classes you can define them when you register a tool:

```php
// in app/Providers/NovaServiceProvider.php

// ...

public function tools()
{
    return [
        // ...
        \Vyuldashev\NovaPermission\NovaPermissionTool::make()
            ->roleResource(CustomRole::class)
            ->permissionResource(CustomPermission::class),
    ];
}

```

If you want to show your roles and policies with a custom label, you can set `$labelAttribute` when instantiating your fields:

```php
// ...
use Vyuldashev\NovaPermission\PermissionBooleanGroup;
use Vyuldashev\NovaPermission\RoleSelect;

public function fields(Request $request)
{
    return [
        // ...
        RoleBooleanGroup::make('Roles', 'roles', null, 'description'),
        PermissionBooleanGroup::make('Permissions', 'permissions', null, 'description'),
        RoleSelect::make('Role', 'roles', null, 'description'),
    ];
}
```


## Define Policies 

```php
// in app/Providers/NovaServiceProvider.php

// ...

public function tools()
{
    return [
        // ...
        \Vyuldashev\NovaPermission\NovaPermissionTool::make()
            ->rolePolicy(RolePolicy::class)
            ->permissionPolicy(PermissionPolicy::class),
    ];
}

```

## Usage

A new menu item called "Permissions & Roles" will appear in your Nova app after installing this package.
