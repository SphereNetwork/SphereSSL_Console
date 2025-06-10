using SphereSSL.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SphereSSL.View
{
    public class Spheressl
    {
        public static async Task MainMenu()
        {

            await UI.PrintIntroductionScreen();

            UI.PrintMainSelection();
           

            var choice = Console.ReadLine();

            switch (choice)
            {
                case "1":

                    await AcmeService.CreateCert();
                    return;
                case "2":
                    UI.LearnMore();
                    Console.ReadLine();
                    return;
                case "3":
                    Environment.Exit(0);
                    return;
                default:
                    Console.WriteLine("Invalid choice. Please try again.");
                    return;
            }
        }


        internal static string GenerateCertRequestId()
        {
            byte[] randomBytes = new byte[32];

            RandomNumberGenerator.Fill(randomBytes);

            return BitConverter.ToString(randomBytes).Replace("-", "").ToLower();
        }

        internal static string PromptFor(string label)
        {
            string input;
            do
            {
                Console.Write($"Enter your {label}: ");
                input = Console.ReadLine()?.Trim();

                if (string.IsNullOrWhiteSpace(input))
                {
                    Console.WriteLine($"❌ You must enter a valid {label}.");
                }

            } while (string.IsNullOrWhiteSpace(input));

            return input;
        }
    }
}
