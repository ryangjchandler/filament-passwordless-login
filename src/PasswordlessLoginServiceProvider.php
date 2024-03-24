<?php

namespace C6Digital\PasswordlessLogin;

use C6Digital\PasswordlessLogin\Facades\PasswordlessLogin;
use C6Digital\PasswordlessLogin\Testing\TestsPasswordlessLogin;
use Filament\Support\Assets\AlpineComponent;
use Filament\Support\Assets\Asset;
use Filament\Support\Assets\Css;
use Filament\Support\Assets\Js;
use Filament\Support\Facades\FilamentAsset;
use Filament\Support\Facades\FilamentIcon;
use Livewire\Features\SupportTesting\Testable;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class PasswordlessLoginServiceProvider extends PackageServiceProvider
{
    public static string $name = 'filament-passwordless-login';

    public static string $viewNamespace = 'filament-passwordless-login';

    public function configurePackage(Package $package): void
    {
        $package->name(static::$name);

        if (file_exists($package->basePath('/../resources/lang'))) {
            $package->hasTranslations();
        }

        $package->hasConfigFile();

        if (file_exists($package->basePath('/../resources/views'))) {
            $package->hasViews(static::$viewNamespace);
        }

        $package->hasCommands([
            Commands\PasswordlessLinkCommand::class,
        ]);
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(PasswordlessLogin::class);
    }

    public function packageBooted(): void
    {
        // Asset Registration
        FilamentAsset::register(
            $this->getAssets(),
            $this->getAssetPackageName()
        );

        FilamentAsset::registerScriptData(
            $this->getScriptData(),
            $this->getAssetPackageName()
        );

        // Icon Registration
        FilamentIcon::register($this->getIcons());

        // Testing
        Testable::mixin(new TestsPasswordlessLogin());
    }

    protected function getAssetPackageName(): ?string
    {
        return 'ryangjchandler/filament-passwordless-login';
    }

    /**
     * @return array<Asset>
     */
    protected function getAssets(): array
    {
        return [
            // AlpineComponent::make('filament-passwordless-login', __DIR__ . '/../resources/dist/components/filament-passwordless-login.js'),
            Css::make('filament-passwordless-login-styles', __DIR__ . '/../resources/dist/filament-passwordless-login.css'),
            Js::make('filament-passwordless-login-scripts', __DIR__ . '/../resources/dist/filament-passwordless-login.js'),
        ];
    }

    /**
     * @return array<class-string>
     */
    protected function getCommands(): array
    {
        return [];
    }

    /**
     * @return array<string>
     */
    protected function getIcons(): array
    {
        return [];
    }

    /**
     * @return array<string>
     */
    protected function getRoutes(): array
    {
        return [];
    }

    /**
     * @return array<string, mixed>
     */
    protected function getScriptData(): array
    {
        return [];
    }

    /**
     * @return array<string>
     */
    protected function getMigrations(): array
    {
        return [];
    }
}
