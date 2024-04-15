<?php

namespace C6Digital\PasswordlessLogin\Mail;

use App\Models\User;
use C6Digital\PasswordlessLogin\Facades\PasswordlessLogin;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class LoginLink extends Mailable
{
    use Queueable;
    use SerializesModels;

    public function __construct(
        public User $user,
    ) {
    }

    public function envelope()
    {
        return new Envelope(
            subject: __('filament-passwordless-login::passwordless-login.mail_subject'),
        );
    }

    public function content()
    {
        return new Content(
            markdown: 'filament-passwordless-login::mail.login-link',
            with: [
                'url' => PasswordlessLogin::generateLoginLink($this->user),
            ]
        );
    }
}
