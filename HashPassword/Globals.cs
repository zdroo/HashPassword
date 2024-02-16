using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace HashPassword
{
    public static class Globals
    {
        public const int SaltByteSize = 32;
        public const int HashByteSize = 32;
        public const int Pbkdf2Iterations = 15641;

        private static byte[] GetPbkd2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            Rfc2898DeriveBytes pbkd2 = new Rfc2898DeriveBytes(password, salt)
            {
                IterationCount = iterations
            };
            return pbkd2.GetBytes(outputBytes);
        }
        public static string HashPassword(string password)
        {
            RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[SaltByteSize];
            cryptoProvider.GetBytes(salt);

            byte[] hash = GetPbkd2Bytes(password, salt, Pbkdf2Iterations, HashByteSize);
            return Convert.ToBase64String(hash) + ":" + Convert.ToBase64String(salt);
        }
        private static bool SlowEquals(IReadOnlyList<byte> a, IReadOnlyList<byte> b)
        {
            uint diff = (uint)a.Count ^ (uint)b.Count;
            for (int i = 0; i < a.Count && i < b.Count; i++)
            {
                diff |= (uint)a[i] ^ (uint)b[i];
            }
            return diff == 0;
        }
        public static bool ValidatePassword(string password, string correctHash, string salt)
        {
            char[] delimiter = { ':' };
            string[] split = correctHash.Split(delimiter);
            byte[] hash = Convert.FromBase64String(split[0]);
            byte[] newSalt = Convert.FromBase64String(salt);

            byte[] testHash = GetPbkd2Bytes(password, newSalt, Pbkdf2Iterations, hash.Length);
            return SlowEquals(hash, testHash);
        }
    }
}
