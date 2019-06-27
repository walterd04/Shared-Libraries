using Microsoft.AspNetCore.Identity;
using PasswordEncryptor.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordEncryptor.Implementation
{
    public class BCryptPasswordEncryption<T> : SimplePasswordEncryption<T> where T : class
    {
        private readonly BCryptPasswordSettings _settings; 
        public BCryptPasswordEncryption(BCryptPasswordSettings settings)
        {
            _settings = settings;
        }

        public override PasswordVerificationResult VerifyHashedPassword(T user, string hashedPassword, string providedPassword)
        {
            if (hashedPassword is null) throw new ArgumentNullException(nameof(hashedPassword));
            if (providedPassword is null) throw new ArgumentNullException(nameof(providedPassword));

            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);

            if (decodedHashedPassword.Length == 0) return PasswordVerificationResult.Failed;

            if (decodedHashedPassword[0] == 0xFF)
            {
                if (VerifyHashedPasswordBcrypt(decodedHashedPassword, providedPassword))
                {
                    return _settings.RehashPasswords ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Success;
                } else
                {
                    return PasswordVerificationResult.Failed;
                }
            }

            return base.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }

        public static bool VerifyHashedPasswordBcrypt(byte[] hashedPassword, string providedPassword)
        {
            if (hashedPassword.Length < 2) return false;

            var storedHash = Encoding.UTF8.GetString(hashedPassword, 1, hashedPassword.Length - 1);

            return BCrypt.Net.BCrypt.Verify(providedPassword, storedHash);
        }
    }

    public class BCryptPasswordSettings
    {
        public bool RehashPasswords { get; set; }
    }
}
