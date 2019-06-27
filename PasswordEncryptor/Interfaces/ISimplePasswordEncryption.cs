using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordEncryptor.Interfaces
{
    public interface ISimplePasswordEncryption<T> where T : class
    {
        string HashPassword(T user, string password);
        PasswordVerificationResult VerifyHashedPassword(T user, string hashedPassword, string providedPassword);
    }
}
