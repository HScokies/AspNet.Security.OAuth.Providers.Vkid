/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Base64UrlEncoder = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder;

namespace AspNet.Security.OAuth.VkId;

public sealed class VkIdAuthenticationHandler : OAuthHandler<VkIdAuthenticationOptions>
{
    [Obsolete("Obsolete")]
    public VkIdAuthenticationHandler(IOptionsMonitor<VkIdAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    public VkIdAuthenticationHandler(IOptionsMonitor<VkIdAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
    {
        var parameter = Options.Scope;
        var scopes = FormatScope(parameter);

        var data = new byte[32];
        RandomNumberGenerator.Fill((Span<byte>)data);
        var codeVerifierKey = Base64UrlEncoder.Encode(data);
        properties.Items.Add(OAuthConstants.CodeVerifierKey, codeVerifierKey);

        var query = new Dictionary<string, string?>
        {
            { "response_type", "code" },
            { "client_id", Options.ClientId },
            { "scope", scopes },
            { "redirect_uri", redirectUri },
            { "state", Options.StateDataFormat.Protect(properties) },
            { "code_challenge", WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifierKey))) },
            { "code_challenge_method", OAuthConstants.CodeChallengeMethodS256 },
        };
        return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, query);
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);
        if (properties is null)
        {
            return HandleRequestResult.Fail(VkIdAuthenticationErrors.InvalidOAuthState);
        }

        if (ValidateCorrelationId(properties) is false)
        {
            return HandleRequestResult.Fail(VkIdAuthenticationErrors.CorrelationFailed);
        }

        var code = Request.Query["code"];
        if (StringValues.IsNullOrEmpty(code))
        {
            return HandleRequestResult.Fail(VkIdAuthenticationErrors.MissingCode);
        }

        var deviceId = Request.Query["device_id"];
        if (StringValues.IsNullOrEmpty(deviceId))
        {
            return HandleRequestResult.Fail(VkIdAuthenticationErrors.MissingDeviceId);
        }

        properties.Items.Add(VkIdAuthenticationConstants.AuthenticationProperties.DeviceId, deviceId);
        var codeExchangeContext =
            new OAuthCodeExchangeContext(properties, code!, BuildRedirectUri(Options.CallbackPath));
        using var tokens = await ExchangeCodeAsync(codeExchangeContext);
        if (tokens.Error is not null)
        {
            return HandleRequestResult.Fail(tokens.Error, properties);
        }

        if (string.IsNullOrEmpty(tokens.AccessToken))
        {
            return HandleRequestResult.Fail(VkIdAuthenticationErrors.MissingAccessToken, properties);
        }

        if (string.IsNullOrEmpty(tokens.RefreshToken))
        {
            return HandleRequestResult.Fail(VkIdAuthenticationErrors.MissingRefreshToken, properties);
        }

        if (Options.SaveTokens)
        {
            var tokensToStore = new List<AuthenticationToken>
            {
                new() { Name = "access_token", Value = tokens.AccessToken, },
                new() { Name = "refresh_token", Value = tokens.RefreshToken, },
            };

            if (tokens.Response!.RootElement.GetString("id_token") is { } idToken)
            {
                tokensToStore.Add(new AuthenticationToken { Name = "id_token", Value = idToken });
            }

            if (!string.IsNullOrEmpty(tokens.TokenType))
            {
                tokensToStore.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
            }

            if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresIn))
            {
                var expiresAt = TimeProvider.GetUtcNow() + TimeSpan.FromSeconds(expiresIn);
                tokensToStore.Add(new AuthenticationToken
                {
                    Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                });
            }

            properties.StoreTokens(tokensToStore);
        }

        var identity = new ClaimsIdentity(ClaimsIssuer);
        var ticket = await CreateTicketAsync(identity, properties, tokens);
        return HandleRequestResult.Success(ticket);
    }

    protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
    {
        if (!context.Properties.Items.TryGetValue(VkIdAuthenticationConstants.AuthenticationProperties.DeviceId,
                out var deviceId) ||
            string.IsNullOrEmpty(deviceId))
        {
            return OAuthTokenResponse.Failed(new Exception(VkIdAuthenticationErrors.MissingDeviceId));
        }

        if (!context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier) ||
            string.IsNullOrEmpty(codeVerifier))
        {
            return OAuthTokenResponse.Failed(new Exception(VkIdAuthenticationErrors.MissingCodeVerifierKey));
        }

        context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
        var query = new Dictionary<string, string>()
        {
            { "grant_type", "authorization_code" },
            { "code", context.Code },
            { "code_verifier", codeVerifier },
            { "client_id", Options.ClientId },
            { "device_id", deviceId },
            { "redirect_uri", context.RedirectUri },
            { "state", Options.StateDataFormat.Protect(context.Properties) },
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(query);
        request.Version = Backchannel.DefaultRequestVersion;

        var response = await Backchannel.SendAsync(request, Context.RequestAborted);
        var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        if (!payload.RootElement.TryGetProperty("state", out var state) ||
            Options.StateDataFormat.Unprotect(state.GetString()) is null)
        {
            return OAuthTokenResponse.Failed(new Exception(VkIdAuthenticationErrors.InvalidOAuthState));
        }

        if (!payload.RootElement.TryGetProperty("error", out var errorElement))
        {
            return OAuthTokenResponse.Success(payload);
        }

        var errorCode = errorElement.GetString()!;
        var errorDescription = errorElement.GetProperty("error_description").GetString()!;
        return OAuthTokenResponse.Failed(new Exception($"{errorCode}: {errorDescription}"));
    }

    protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
    {
        var query = new Dictionary<string, string>
        {
            { "access_token", tokens.AccessToken! }, { "client_id", Options.ClientId }
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, Options.UserInformationEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(query);
        request.Version = Backchannel.DefaultRequestVersion;

        var response = await Backchannel.SendAsync(request, Context.RequestAborted);
        var content = await response.Content.ReadAsStringAsync();
        var body = JsonDocument.Parse(content);

        if (body.RootElement.TryGetProperty("error", out var errorElement))
        {
            var error = errorElement.GetString();
            var errorDescription = body.RootElement.GetProperty("error_description").GetString();
            throw new Exception($"{error} - {errorDescription}");
        }

        if (!body.RootElement.TryGetProperty("user", out var payload))
        {
            throw new Exception(VkIdAuthenticationErrors.FailedToRetrieveUserInfo);
        }

        var principal = new ClaimsPrincipal(identity);
        var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload);
        context.RunClaimActions();

        await Events.CreatingTicket(context);
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }
}
