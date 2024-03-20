# Simple passwordless login for Filament.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/ryangjchandler/filament-passwordless-login.svg?style=flat-square)](https://packagist.org/packages/ryangjchandler/filament-passwordless-login)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/ryangjchandler/filament-passwordless-login/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/ryangjchandler/filament-passwordless-login/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/ryangjchandler/filament-passwordless-login/fix-php-code-style-issues.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/ryangjchandler/filament-passwordless-login/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/ryangjchandler/filament-passwordless-login.svg?style=flat-square)](https://packagist.org/packages/ryangjchandler/filament-passwordless-login)

This package provides a new Login component that replaces the traditional email and password form with a simple passwordless login form.

## Installation

You can install the package via composer:

```bash
composer require c6digital/filament-passwordless-login
```

Optionally, you can publish the views using

```bash
php artisan vendor:publish --tag="filament-passwordless-login-views"
```

## Usage

Register the plugin on your Filament panel.

```php
use C6Digital\PasswordlessLogin\PasswordlessLoginPlugin;

public function panel(Panel $panel): Panel
{
    return $panel
        ->//...
        ->plugin(PasswordlessLoginPlugin::make());
}
```

This will automatically register the new login page, overwriting the one provided by Filament. It also registers the necessary routes to authenticate users using a magic login link.

### Using password in local environments

Sending login links emails during development can be difficult. If you are still storing passwords for your users, you can enable password authentication in `local` environments.

```php
PasswordlessLoginPlugin::make()
    ->allowPasswordInLocalEnvironment()
```

Now a "Password" field will be displayed on the Login page when `APP_ENV=local`.

### Action

This package also provides an `Action` that can be used inside of Filament tables.

```php
use C6Digital\PasswordlessLogin\Actions\LoginLinkAction;

$table
    ->actions([
        LoginLinkAction::make(),
    ]);
```

### Command

If you need to generate a login link without accessing the site, you can use the `passwordless:link` command.

```sh
php artisan passwordless:link {email}
```

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Ryan Chandler](https://github.com/ryangjchandler)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
