/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
*/

namespace AspNet.Security.OAuth.VkId;

public static class VkIdAuthenticationErrors
{
    public const string InvalidOAuthState = "The oauth state was missing or invalid.";
    public const string CorrelationFailed = "Correlation failed.";
    public const string MissingCode = "Code was not found.";
    public const string MissingDeviceId = "DeviceId was not found.";
    public const string MissingCodeVerifierKey = "Code verifier key was not found.";
    public const string MissingAccessToken = "Failed to retrieve access_token.";
    public const string MissingRefreshToken = "Failed to retrieve refresh_token.";
    public const string FailedToRetrieveUserInfo = "Failed to retrieve user information.";
}
