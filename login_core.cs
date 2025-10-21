// LoginCore.cs
// Instance-based, DI-friendly login/auth flow with no statics.
// Drop this file into a .NET (Windows) project. Replace placeholders in ApiOptions.
//
// Dependencies:
//   • System.Net.Http
//   • System.Security.Cryptography
//   • (Optional) System.Management if you enable the WMI-based HardwareIdProvider
//   • The SimpleCrypto.cs file from this repo for encryption helpers
//
// Notes:
//   - No hard-coded domains, keys, or identifiers. Fill ApiOptions and RSAPublicKeyXml.
//   - Uses async/await, CancellationToken, and interfaces for easy testing.
//   - All state is instance-scoped; no static mutable fields.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace StupidSimpleAuth
{
    #region Options & Models

    public sealed class ApiOptions
    {
        public Uri BaseUri { get; init; } = new Uri("https://api.example.com/");
        public string InitPath { get; init; } = "v1/init";  // server nonce+session
        public string LoginPath { get; init; } = "v1/login"; // login endpoint
        public string ClientVersion { get; init; } = "1.0.0"; // your app version
        public string RSAPublicKeyXml { get; init; } = @"<RSAKeyValue><Modulus>...</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"; // replace
    }

    public sealed class InitRequest
    {
        public string Type { get; init; } = "I";
        public string Version { get; init; } = "1.0.0";
        public string Key { get; init; } = string.Empty; // client nonce / composite
    }

    public sealed class InitResponse
    {
        public string Message { get; set; } = string.Empty;    // JSON payload (string)
        public string SignatureBase64 { get; set; } = string.Empty; // Signature over Message
    }

    public sealed class LoginRequest
    {
        public string Type { get; init; } = "login";
        public string Session { get; init; } = string.Empty;
        public string Username { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string HardwareId { get; init; } = string.Empty;
        public int Mix { get; init; }
    }

    public sealed class ServerEnvelope
    {
        public string Status { get; set; } = "";    // e.g. "ok"
        public string Uid { get; set; } = "";
        public string Username { get; set; } = "";
        public string HardwareId { get; set; } = "";
        public string Session { get; set; } = "";
        public string SubscriptionUntil { get; set; } = "";  // yyyy-MM-dd HH:mm:ss
        public string ServerTime { get; set; } = "";         // yyyy-MM-dd HH:mm:ss
        public int Deb { get; set; }                           // echo of Mix
    }

    public sealed class LoginResult
    {
        public bool Success { get; init; }
        public string? Error { get; init; }
        public ServerEnvelope? Envelope { get; init; }
    }

    #endregion

    #region Interfaces

    public interface ITimeProvider
    {
        DateTime UtcNow { get; }
    }

    public interface IRandomProvider
    {
        int NextInt(int minInclusive, int maxExclusive);
        long NextLong();
        byte[] GetBytes(int count);
    }

    public interface IHardwareIdProvider
    {
        string GetHardwareId();
    }

    public interface ICryptoFacade
    {
        // Symmetric helpers are routed to your SimpleCrypto implementation
        string EncryptToBase64(string plaintext, byte[] key, byte[] salt = null);
        string DecryptFromBase64(string base64Blob, byte[] key);
        byte[] Sha256(byte[] bytes);
        bool VerifyRsaSignature(string publicKeyXml, byte[] dataUtf8, byte[] signature);
    }

    public interface IApiClient
    {
        Task<TResponse> PostJsonAsync<TRequest, TResponse>(Uri baseUri, string path, TRequest request, CancellationToken ct);
    }

    #endregion

    #region Default Implementations

    public sealed class SystemTimeProvider : ITimeProvider
    {
        public DateTime UtcNow => DateTime.UtcNow;
    }

    public sealed class SecureRandomProvider : IRandomProvider
    {
        public int NextInt(int minInclusive, int maxExclusive)
        {
            if (minInclusive >= maxExclusive) throw new ArgumentOutOfRangeException();
            // uniform int in range using cryptographically secure random
            Span<byte> b = stackalloc byte[4];
            RandomNumberGenerator.Fill(b);
            uint val = BitConverter.ToUInt32(b);
            uint range = (uint)(maxExclusive - minInclusive);
            return (int)(val % range) + minInclusive;
        }
        public long NextLong()
        {
            Span<byte> b = stackalloc byte[8];
            RandomNumberGenerator.Fill(b);
            return (long)BitConverter.ToUInt64(b);
        }
        public byte[] GetBytes(int count)
        {
            byte[] data = new byte[count];
            RandomNumberGenerator.Fill(data);
            return data;
        }
    }

    public sealed class DefaultCryptoFacade : ICryptoFacade
    {
        public string EncryptToBase64(string plaintext, byte[] key, byte[] salt = null)
            => SimpleCrypto.SimpleCrypto.EncryptToBase64(plaintext, key, salt);
        public string DecryptFromBase64(string base64Blob, byte[] key)
            => SimpleCrypto.SimpleCrypto.DecryptFromBase64(base64Blob, key);
        public byte[] Sha256(byte[] bytes)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(bytes);
        }
        public bool VerifyRsaSignature(string publicKeyXml, byte[] dataUtf8, byte[] signature)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(publicKeyXml);
            return rsa.VerifyData(dataUtf8, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public sealed class HttpClientApi : IApiClient, IDisposable
    {
        private readonly HttpClient _http;
        public HttpClientApi(HttpMessageHandler handler = null)
        {
            _http = handler == null ? new HttpClient() : new HttpClient(handler);
        }
        public async Task<TResponse> PostJsonAsync<TRequest, TResponse>(Uri baseUri, string path, TRequest request, CancellationToken ct)
        {
            _http.BaseAddress = baseUri;
            using var content = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(path, content, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<TResponse>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        }
        public void Dispose() => _http.Dispose();
    }

    public sealed class BasicHardwareIdProvider : IHardwareIdProvider
    {
        // Non-PII-ish sample: machine + user + OS + one drive serial (if available)
        public string GetHardwareId()
        {
            var parts = new List<string>
            {
                Environment.MachineName,
                Environment.UserName,
                Environment.OSVersion.VersionString
            };

            try
            {
                // Try to read C: volume serial in a portable way
                var drive = DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase));
                if (drive != null)
                {
                    parts.Add(drive.TotalSize.ToString());
                    parts.Add(drive.DriveFormat);
                }
            }
            catch { /* best-effort only */ }

            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(string.Join("|", parts)));
            return string.Concat(hash.Select(b => b.ToString("x2")));
        }
    }

    #endregion

    #region Login Service

    public sealed class LoginService
    {
        private readonly ApiOptions _opts;
        private readonly IApiClient _api;
        private readonly ICryptoFacade _crypto;
        private readonly IRandomProvider _rng;

        public LoginService(ApiOptions opts, IApiClient api, ICryptoFacade crypto, IRandomProvider rng)
        {
            _opts = opts ?? throw new ArgumentNullException(nameof(opts));
            _api = api ?? throw new ArgumentNullException(nameof(api));
            _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
            _rng = rng ?? throw new ArgumentNullException(nameof(rng));
        }

        public async Task<LoginResult> LoginAsync(string username, string password, IHardwareIdProvider hwid, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(username)) return new LoginResult { Success = false, Error = "Username required" };
            if (string.IsNullOrWhiteSpace(password)) return new LoginResult { Success = false, Error = "Password required" };

            // 1) Init handshake – make a composite nonce/key and send to server
            long p = _rng.NextLong();
            long a = _rng.NextLong();
            long mix = _rng.NextInt(1, int.MaxValue);
            long composite = unchecked(p * a * mix);

            var initReq = new InitRequest
            {
                Version = _opts.ClientVersion,
                Key = composite.ToString()
            };

            InitResponse initResp;
            try
            {
                initResp = await _api.PostJsonAsync<InitRequest, InitResponse>(_opts.BaseUri, _opts.InitPath, initReq, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new LoginResult { Success = false, Error = $"Init failed: {ex.Message}" };
            }

            // 2) Verify server signature over the JSON payload
            if (!TryVerifySignedMessage(initResp, _opts.RSAPublicKeyXml, _crypto, out var initPayloadJson, out string verifyErr))
                return new LoginResult { Success = false, Error = verifyErr };

            // 3) Derive a session key from the composite (simple SHA256 for demo; you may upgrade)
            byte[] akey = _crypto.Sha256(Encoding.UTF8.GetBytes(((composite).ToString())));

            // 4) Build login request
            string session = JsonDocument.Parse(initPayloadJson).RootElement.GetProperty("session").GetString() ?? string.Empty;
            var req = new LoginRequest
            {
                Session = session,
                Username = username,
                Password = password,
                HardwareId = hwid.GetHardwareId(),
                Mix = (int)(mix & 0x7FFFFFFF)
            };

            // 5) Post login
            InitResponse loginEnvelope; // reuse InitResponse shape (Message + Signature)
            try
            {
                loginEnvelope = await _api.PostJsonAsync<LoginRequest, InitResponse>(_opts.BaseUri, _opts.LoginPath, req, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new LoginResult { Success = false, Error = $"Login failed: {ex.Message}" };
            }

            if (!TryVerifySignedMessage(loginEnvelope, _opts.RSAPublicKeyXml, _crypto, out var loginPayloadJson, out verifyErr))
                return new LoginResult { Success = false, Error = verifyErr };

            // 6) Parse and validate server envelope
            ServerEnvelope env;
            try
            {
                env = JsonSerializer.Deserialize<ServerEnvelope>(loginPayloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            }
            catch (Exception ex)
            {
                return new LoginResult { Success = false, Error = $"Invalid server payload: {ex.Message}" };
            }

            if (!string.Equals(env.Username, username, StringComparison.Ordinal))
                return new LoginResult { Success = false, Error = "Username mismatch." };
            if (!string.Equals(env.Session, session, StringComparison.Ordinal))
                return new LoginResult { Success = false, Error = "Session mismatch." };
            if (env.Deb != req.Mix)
                return new LoginResult { Success = false, Error = "Mix/nonce mismatch." };

            // Optional: subscription check
            if (DateTime.TryParse(env.SubscriptionUntil, out var until) && DateTime.TryParse(env.ServerTime, out var now))
            {
                if (until <= now) return new LoginResult { Success = false, Error = "Subscription expired." };
            }

            return new LoginResult { Success = true, Envelope = env };
        }

        private static bool TryVerifySignedMessage(InitResponse resp, string publicKeyXml, ICryptoFacade crypto, out string messageJson, out string error)
        {
            messageJson = string.Empty; error = string.Empty;
            if (string.IsNullOrWhiteSpace(resp.Message)) { error = "Empty server message."; return false; }
            if (string.IsNullOrWhiteSpace(resp.SignatureBase64)) { error = "Empty server signature."; return false; }
            byte[] data = Encoding.UTF8.GetBytes(resp.Message);
            byte[] sig;
            try { sig = Convert.FromBase64String(resp.SignatureBase64); }
            catch { error = "Malformed signature."; return false; }

            bool ok;
            try { ok = crypto.VerifyRsaSignature(publicKeyXml, data, sig); }
            catch (Exception ex) { error = $"Signature verification error: {ex.Message}"; return false; }

            if (!ok) { error = "Signature verification failed."; return false; }
            messageJson = resp.Message; return true;
        }
    }

    #endregion

    #region Minimal WinForms usage (optional)

    // Example of wiring this in a form (pseudo-simplified; put in your Form code-behind):
    //
    //   var service = new LoginService(
    //       new ApiOptions { BaseUri = new Uri("https://api.example.com/"), RSAPublicKeyXml = "..." },
    //       new HttpClientApi(),
    //       new DefaultCryptoFacade(),
    //       new SecureRandomProvider());
    //
    //   var hwid = new BasicHardwareIdProvider();
    //   var result = await service.LoginAsync(txtUser.Text, txtPass.Text, hwid, this._cts.Token);
    //   if (result.Success) { /* proceed */ } else { MessageBox.Show(result.Error); }

    #endregion
}
