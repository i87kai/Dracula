using System;
using System.Runtime.InteropServices;

namespace Dracula.ManagedFixture
{
    public interface ISampleService
    {
        bool Authenticate(string username, string password);
    }

    public class SecurityManager : ISampleService
    {
        private readonly string _secretKey = "DRACULA_CONFIDENTIAL_KEY_98765";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern uint GetCurrentProcessId();

        public bool Authenticate(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return false;
            }
            return username == "analyst" && password == "dracula2026";
        }

        public string GetSecretToken()
        {
            return _secretKey;
        }

        public static int CalculateHash(int seed)
        {
            return (seed * 397) ^ 0x5F3759DF;
        }
    }
}
