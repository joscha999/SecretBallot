namespace SecretBallot.Server.Auth;

public static class ReturnUrl {
    public static bool IsLocal(string? url) {
        if (string.IsNullOrEmpty(url) || url[0] != '/')
            return false;
        if (url.Any(c => char.IsControl(c) || c == '\\'))
            return false;
        return url.Length == 1 || url[1] != '/';
    }
}
