using System.Diagnostics;

namespace SecretBallot.Server.Tests.EndToEnd;

public class EndToEndTests {
    [Test]
    [Arguments(1)]
    [Arguments(4)]
    public async Task Full_election_runs_through_browser_crypto_and_verifies(int holderCount) {
        await using var factory = new BallotServerFactory();
        factory.UseKestrel(0);
        factory.StartServer();
        var baseUrl = factory.ClientOptions.BaseAddress.ToString().TrimEnd('/');

        var (exitCode, output) = await RunNodeAsync(baseUrl, holderCount);

        await Assert.That(output).Contains($"E2E OK with {holderCount} key holders");
        await Assert.That(exitCode).IsEqualTo(0);
    }

    private static async Task<(int ExitCode, string Output)> RunNodeAsync(string baseUrl, int holderCount) {
        var root = FindRepositoryRoot();
        var start = new ProcessStartInfo("node") {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add(Path.Combine(root, "tests-js", "e2e", "flow.js"));
        start.ArgumentList.Add(baseUrl);
        start.ArgumentList.Add(holderCount.ToString());

        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await stdout + await stderr);
    }

    private static string FindRepositoryRoot() {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "SecretBallot.slnx")))
            directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("SecretBallot.slnx not found above the test binaries");
    }
}
