<?php

namespace C6Digital\PasswordlessLogin\Tests\Classes;

use C6Digital\PasswordlessLogin\PasswordlessLoginExpiration;
use Illuminate\Support\Carbon;

class ExtendedPasswordlessLoginExpiration implements PasswordlessLoginExpiration
{
    public function expiration(): Carbon
    {
        return now()->addYears(2);
    }
}
