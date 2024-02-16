using System;

namespace HashPassword
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Introduce your password: ");
            var pass = Console.ReadLine();
            var hashedPass = PasswordHashPBKDF2.HashPassword(pass);
            Console.WriteLine($"Your hashed password is: {hashedPass}");
            Console.WriteLine("Write your password again: ");

            bool isValid = PasswordHashPBKDF2.ValidatePassword(Console.ReadLine(), hashedPass);
            Console.WriteLine(isValid ? "The password is correct." : "Wrong password.");
            Console.ReadLine();

        }
    }
}
