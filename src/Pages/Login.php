<?php

namespace C6Digital\PasswordlessLogin\Pages;

use App\Models\User;
use C6Digital\PasswordlessLogin\Mail\LoginLink;
use C6Digital\PasswordlessLogin\PasswordlessLoginPlugin;
use Filament\Actions\Action;
use Filament\Facades\Filament;
use Filament\Forms\Components\Component;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Form;
use Filament\Http\Responses\Auth\Contracts\LoginResponse;
use Filament\Models\Contracts\FilamentUser;
use Filament\Pages\Concerns\InteractsWithFormActions;
use Filament\Pages\SimplePage;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;

class Login extends SimplePage
{
    use InteractsWithFormActions;

    protected static string $view = 'filament-passwordless-login::pages.login';

    public $email;

    public $password;

    public $sent = false;

    public function mount()
    {
        if (Filament::auth()->check()) {
            return redirect()->intended(Filament::getUrl());
        }

        $this->form->fill();
    }

    public function authenticate()
    {
        $data = $this->form->getState();

        if (PasswordlessLoginPlugin::get()->allowsPasswordInLocalEnvironment() && !blank($data['password'])) {
            return $this->authenticateWithPassword($data);
        }

        $user = User::query()
            ->where('email', $data['email'])
            ->first();

        if ($user !== null) {
            Mail::to($data['email'])->queue(new LoginLink($user));
        }

        $this->sent = true;

        $this->reset('email');
    }

    protected function authenticateWithPassword(array $data)
    {
        if (! PasswordlessLoginPlugin::get()->allowsPasswordInLocalEnvironment()) {
            return;
        }

        if (! Filament::auth()->attempt($this->getCredentialsFromFormData($data))) {
            $this->throwFailureValidationException();
        }

        $user = Filament::auth()->user();

        if (
            ($user instanceof FilamentUser) &&
            (!$user->canAccessPanel(Filament::getCurrentPanel()))
        ) {
            Filament::auth()->logout();

            $this->throwFailureValidationException();
        }

        Session::regenerate();

        return app(LoginResponse::class);
    }

    protected function throwFailureValidationException(): never
    {
        throw ValidationException::withMessages([
            'email' => __('filament-panels::pages/auth/login.messages.failed'),
        ]);
    }

    public function form(Form $form): Form
    {
        return $form
            ->schema([
                $this->getEmailFormComponent(),
                $this->getPasswordFormComponent(),
            ]);
    }

    protected function getEmailFormComponent(): Component
    {
        return TextInput::make('email')
            ->label(__('filament-panels::pages/auth/login.form.email.label'))
            ->email()
            ->required()
            ->autocomplete()
            ->autofocus()
            ->extraInputAttributes(['tabindex' => 1]);
    }

    protected function getPasswordFormComponent(): Component
    {
        return TextInput::make('password')
            ->visible(fn () => PasswordlessLoginPlugin::get()->allowsPasswordInLocalEnvironment())
            ->label(__('filament-panels::pages/auth/login.form.password.label'))
            ->helperText('You are currently in a local environment, so you can use a password instead of a login link.')
            ->password()
            ->revealable(filament()->arePasswordsRevealable())
            ->autocomplete('current-password')
            ->extraInputAttributes(['tabindex' => 2]);
    }

    protected function getFormActions(): array
    {
        return [
            $this->getAuthenticateFormAction(),
        ];
    }

    protected function getAuthenticateFormAction(): Action
    {
        return Action::make('authenticate')
            ->label(__('filament-panels::pages/auth/login.form.actions.authenticate.label'))
            ->submit('authenticate');
    }

    protected function hasFullWidthFormActions(): bool
    {
        return true;
    }

    protected function getCredentialsFromFormData(array $data): array
    {
        return [
            'email' => $data['email'],
            'password' => $data['password'],
        ];
    }

    protected function messages()
    {
        return [
            'email.required' => 'Please enter your email address.',
            'email.email' => 'Please enter a valid email address.',
        ];
    }
}
