<?php

namespace C6Digital\PasswordlessLogin;

use C6Digital\PasswordlessLogin\Exceptions\InvalidExperationClassException;
use Filament\Facades\Filament;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\URL;

class PasswordlessLogin
{
    public function generateLoginLink(Authenticatable $user): string
    {
        $expiration = app(
            config('filament-passwordless-login.link_expiration')
        );

        if (! $expiration instanceof PasswordlessLoginExpiration) {
            throw new InvalidExperationClassException;
        }

        return URL::temporarySignedRoute('filament.' . Filament::getCurrentPanel()->getId() . '.auth.link', $expiration->expiration(), $user);
    }
}
