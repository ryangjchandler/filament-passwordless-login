<?php

use C6Digital\PasswordlessLogin\Facades\PasswordlessLogin;
use C6Digital\PasswordlessLogin\Tests\Classes\ExtendedPasswordlessLoginExpiration;

it('can test', function () {
    expect(true)->toBeTrue();
});

it('can generate link with default duration', function () {

    $user = Mockery::mock(Illuminate\Foundation\Auth\User::class);
    $user->shouldReceive('getRouteKey')->andReturn('id');

    $expires = time() + 30 * 60;

    $link = PasswordlessLogin::generateLoginLink($user);

    $url = parse_url($link);
    parse_str($url['query'], $output);

    $this->assertEquals($output['expires'], $expires);
});

it('can generate link with extended duration', function () {

    $user = Mockery::mock(Illuminate\Foundation\Auth\User::class);
    $user->shouldReceive('getRouteKey')->andReturn('id');

    $expires = time() + 24 * 60 * 60 * 365 * 2;

    config()->set('filament-passwordless-login.link_expiration', ExtendedPasswordlessLoginExpiration::class);

    $link = PasswordlessLogin::generateLoginLink($user);

    $url = parse_url($link);
    parse_str($url['query'], $output);

    $this->assertEquals($output['expires'], $expires);
});
