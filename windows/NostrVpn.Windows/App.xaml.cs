using System.Windows;
using NostrVpn.Windows.Services;
using NostrVpn.Windows.ViewModels;

namespace NostrVpn.Windows;

public partial class App : System.Windows.Application
{
    private SingleInstanceService? _singleInstance;
    private AppViewModel? _viewModel;
    private MainWindow? _window;
    private TrayService? _tray;

    public static bool IsQuitting { get; private set; }

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        _singleInstance = SingleInstanceService.ClaimOrSignal(e.Args);
        if (_singleInstance is null)
        {
            Shutdown();
            return;
        }

        base.OnStartup(e);
        _viewModel = new AppViewModel();
        _window = new MainWindow(_viewModel);
        _tray = new TrayService();
        _tray.Attach(_viewModel, ShowMainWindow, Quit);
        _singleInstance.Start(args => Dispatcher.Invoke(() => HandleLaunchArgs(args, forceShow: true)));

        HandleLaunchArgs(e.Args, forceShow: false);

        if (!e.Args.Contains("--autostart", StringComparer.OrdinalIgnoreCase)
            && !e.Args.Contains("--hidden", StringComparer.OrdinalIgnoreCase))
        {
            ShowMainWindow();
        }
    }

    protected override void OnExit(System.Windows.ExitEventArgs e)
    {
        _singleInstance?.Dispose();
        _tray?.Dispose();
        _viewModel?.Dispose();
        base.OnExit(e);
    }

    private void HandleLaunchArgs(IEnumerable<string> args, bool forceShow)
    {
        var launchArgs = args.ToArray();
        foreach (var arg in launchArgs.Where(arg => arg.StartsWith("nvpn://", StringComparison.OrdinalIgnoreCase)))
        {
            _viewModel?.HandleDeepLink(arg);
        }

        if (forceShow
            && !launchArgs.Contains("--autostart", StringComparer.OrdinalIgnoreCase)
            && !launchArgs.Contains("--hidden", StringComparer.OrdinalIgnoreCase))
        {
            ShowMainWindow();
        }
    }

    private void ShowMainWindow()
    {
        _window ??= new MainWindow(_viewModel ?? new AppViewModel());
        if (_window.WindowState == System.Windows.WindowState.Minimized)
        {
            _window.WindowState = System.Windows.WindowState.Normal;
        }
        _window.Show();
        _window.Activate();
    }

    private void Quit()
    {
        IsQuitting = true;
        Shutdown();
    }
}
