<?php

namespace C6Digital\PasswordlessLogin;

use Illuminate\Support\Carbon;

class DefaultPasswordlessLoginExpiration implements PasswordlessLoginExpiration
{
    public function expiration(): Carbon
    {
        return now()->addMinutes(30);
    }
}
