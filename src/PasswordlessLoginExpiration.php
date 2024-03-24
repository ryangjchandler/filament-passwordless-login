<?php

namespace C6Digital\PasswordlessLogin;

use Illuminate\Support\Carbon;

interface PasswordlessLoginExpiration
{
    public function expiration(): Carbon;
}
