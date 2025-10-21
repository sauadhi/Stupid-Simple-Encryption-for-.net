// SimpleCrypto.cs
// Stupid‑Simple Encryption for .NET (single‑file, drop‑in)
//
// What you get:
//   • PBKDF2 key derivation
//   • Authenticated encryption: AES‑CBC + HMAC‑SHA256 (Encrypt‑then‑MAC)
//   • String helpers (UTF‑8 in, Base64 out)
//   • Random SessionId generator
//   • SHA‑256 hashing helper
// Works on: .NET Framework 4.6+ and all modern .NETs (no AesGcm dependency).
//
// Format (Base64 of binary blob):
//   [1 byte version=0x01]
//   [16 bytes salt]
//   [16 bytes IV]
//   [4 bytes ciphertext length (int32, big‑endian)]
//   [ciphertext]
//   [32 bytes HMAC‑SHA256 over (version||salt||iv||len||ciphertext)]
//
// Usage:
//   // Password‑based
//   string blob = SimpleCrypto.EncryptToBase64("hello", password: "correct horse battery staple");
//   string plain = SimpleCrypto.DecryptFromBase64(blob, password: "correct horse battery staple");
//
//   // Raw key (32‑byte)
//   byte[] key = SimpleCrypto.GenerateKeyFromPassword("pw", out var salt, 32);
//   string blob2 = SimpleCrypto.EncryptToBase64("secret", key, salt);
//   string plain2 = SimpleCrypto.DecryptFromBase64(blob2, key);
//
//   // Utilities
//   string sid = SimpleCrypto.SessionId(16);
//   string sha = SimpleCrypto.Sha256Hex("data");

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SimpleCrypto
{
    public static class SimpleCrypto
    {
        // ===== Public API =====

        // Encrypt with a password (PBKDF2 derives a 32‑byte key). Returns Base64 blob.
        public static string EncryptToBase64(string plaintext, string password, int iterations = 100_000)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (password == null) throw new ArgumentNullException(nameof(password));

            byte[] salt = RandomBytes(16);
            byte[] key = DeriveKey(password, salt, iterations, 32);
            try
            {
                byte[] blob = EncryptInternal(Encoding.UTF8.GetBytes(plaintext), key, salt);
                return Convert.ToBase64String(blob);
            }
            finally
            {
                Zero(key);
            }
        }

        // Decrypt a Base64 blob with a password.
        public static string DecryptFromBase64(string base64Blob, string password, int iterations = 100_000)
        {
            if (base64Blob == null) throw new ArgumentNullException(nameof(base64Blob));
            if (password == null) throw new ArgumentNullException(nameof(password));

            byte[] blob = Convert.FromBase64String(base64Blob);
            ParseHeader(blob, out byte version, out byte[] salt, out byte[] iv, out int ctLen, out int headerLen);
            if (version != Version) throw new CryptographicException("Unsupported blob version.");

            byte[] key = DeriveKey(password, salt, iterations, 32);
            try
            {
                return DecryptChecked(blob, headerLen, ctLen, key);
            }
            finally
            {
                Zero(key);
            }
        }

        // Encrypt with an already‑derived 32‑byte key. Optionally pass a salt to embed (for your own bookkeeping).
        public static string EncryptToBase64(string plaintext, byte[] key, byte[] salt = null)
        {
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 32) throw new ArgumentException("Expected 32‑byte key.", nameof(key));

            salt ??= RandomBytes(16);
            byte[] blob = EncryptInternal(Encoding.UTF8.GetBytes(plaintext), key, salt);
            return Convert.ToBase64String(blob);
        }

        // Decrypt with an already‑derived 32‑byte key.
        public static string DecryptFromBase64(string base64Blob, byte[] key)
        {
            if (base64Blob == null) throw new ArgumentNullException(nameof(base64Blob));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 32) throw new ArgumentException("Expected 32‑byte key.", nameof(key));

            byte[] blob = Convert.FromBase64String(base64Blob);
            ParseHeader(blob, out byte version, out _, out _, out int ctLen, out int headerLen);
            if (version != Version) throw new CryptographicException("Unsupported blob version.");
            return DecryptChecked(blob, headerLen, ctLen, key);
        }

        // Derive a key from password and salt using PBKDF2 (HMAC‑SHA256).
        public static byte[] GenerateKeyFromPassword(string password, out byte[] salt, int keyBytes = 32, int iterations = 100_000)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            salt = RandomBytes(16);
            return DeriveKey(password, salt, iterations, keyBytes);
        }

        // Utility: random SessionId
        public static string SessionId(int length)
        {
            if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var data = RandomBytes(length);
            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++) sb.Append(chars[data[i] % chars.Length]);
            return sb.ToString();
        }

        // Utility: SHA‑256 hex digest
        public static string Sha256Hex(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(text));
                return string.Concat(hash.Select(b => b.ToString("x2")));
            }
        }

        // ===== Internals =====

        private const byte Version = 0x01; // bump if format changes

        private static byte[] EncryptInternal(byte[] plaintext, byte[] key, byte[] salt)
        {
            byte[] iv = RandomBytes(16);
            byte[] cipher;

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();
                    cipher = ms.ToArray();
                }
            }

            // Build header: version|salt|iv|len|cipher
            byte[] lenBE = IntToBigEndian(cipher.Length);
            byte[] header = Concat(new[] { new[] { Version }, salt, iv, lenBE, cipher });

            // HMAC over the whole header
            byte[] hmac = HmacSha256(key, header);
            byte[] blob = Concat(new[] { header, hmac });
            Zero(iv); Zero(lenBE); Zero(plaintext); // best effort
            return blob;
        }

        private static string DecryptChecked(byte[] blob, int headerLen, int ctLen, byte[] key)
        {
            // Verify HMAC
            int hmacOffset = headerLen + ctLen;
            int total = hmacOffset + 32;
            if (blob.Length != total) throw new CryptographicException("Malformed blob (length mismatch).");

            byte[] expected = blob.Skip(hmacOffset).Take(32).ToArray();
            byte[] actual = HmacSha256(key, blob.Take(hmacOffset).ToArray());
            if (!FixedTimeEquals(expected, actual)) throw new CryptographicException("HMAC validation failed.");

            // Parse fields again to get IV and ciphertext
            ParseHeader(blob, out _, out _, out byte[] iv, out _, out int headerLen2);
            byte[] ciphertext = blob.Skip(headerLen2).Take(ctLen).ToArray();

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using var ms = new MemoryStream();
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(ciphertext, 0, ciphertext.Length);
                    cs.FlushFinalBlock();
                    var plain = ms.ToArray();
                    Zero(iv); Zero(ciphertext);
                    return Encoding.UTF8.GetString(plain);
                }
            }
        }

        private static void ParseHeader(byte[] blob, out byte version, out byte[] salt, out byte[] iv, out int ctLen, out int headerLen)
        {
            if (blob.Length < 1 + 16 + 16 + 4 + 32) throw new CryptographicException("Blob too short.");
            int idx = 0;
            version = blob[idx++];
            salt = blob.Skip(idx).Take(16).ToArray(); idx += 16;
            iv = blob.Skip(idx).Take(16).ToArray(); idx += 16;
            ctLen = BigEndianToInt(blob, idx); idx += 4;
            headerLen = idx; // up to but not including ciphertext
            if (blob.Length < headerLen + ctLen + 32) throw new CryptographicException("Malformed blob.");
        }

        private static byte[] DeriveKey(string password, byte[] salt, int iterations, int keyBytes)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(keyBytes);
        }

        private static byte[] HmacSha256(byte[] key, byte[] data)
        {
            using var h = new HMACSHA256(key);
            return h.ComputeHash(data);
        }

        private static byte[] RandomBytes(int count)
        {
            byte[] b = new byte[count];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        private static byte[] IntToBigEndian(int value)
        {
            unchecked
            {
                return new[]
                {
                    (byte)((value >> 24) & 0xFF),
                    (byte)((value >> 16) & 0xFF),
                    (byte)((value >> 8) & 0xFF),
                    (byte)(value & 0xFF)
                };
            }
        }

        private static int BigEndianToInt(byte[] data, int offset)
        {
            return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
        }

        private static byte[] Concat(byte[][] parts)
        {
            int len = parts.Sum(p => p.Length);
            byte[] result = new byte[len];
            int pos = 0;
            foreach (var p in parts)
            {
                Buffer.BlockCopy(p, 0, result, pos, p.Length);
                pos += p.Length;
            }
            return result;
        }

        private static void Zero(byte[] buffer)
        {
            if (buffer == null) return;
            Array.Clear(buffer, 0, buffer.Length);
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
