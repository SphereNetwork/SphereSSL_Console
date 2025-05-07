using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using ACMESharp.Crypto;
using System.Net.Http;
using System.Security.Cryptography;
using ACMESharp.Crypto.JOSE.Impl;
using Org.BouncyCastle.Asn1.X509;
using DnsClient;
using System.Threading.Tasks;

namespace SphereSSL
{
    public class AcmeService
    {
        private readonly AcmeProtocolClient _client;
        private readonly Uri _directoryUri = new("https://acme-v02.api.letsencrypt.org/directory");
        private AccountDetails _account;

        public AcmeService()
        {
            var http = new HttpClient();
            _client = new AcmeProtocolClient(http);
        }

        public async Task<bool> InitAsync(string email)
        {
            try
            {
                await _client.GetDirectoryAsync();
                await _client.GetNonceAsync();
                await _client.CreateAccountAsync(new[] { $"mailto:{email}" }, true);
                _account = _client.Account;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Account creation failed: {ex.Message}");
                return false;
            }
        }

        public async Task<OrderDetails> BeginOrder(string domain)
        {
            return await _client.CreateOrderAsync(new[] { domain });
        }

        public async Task<string> GetDnsChallengeToken(OrderDetails order)
        {
            var authz = await _client.GetAuthorizationDetailsAsync(order.Payload.Authorizations[0]);
            var dnsChallenge = authz.Challenges.First(c => c.Type == "dns-01");
            return dnsChallenge.Token;
        }

        public async Task<(string Token, string Domain)> CreateUserAccountForCert()
        {
            var acmeService = new AcmeService();
            var order = new OrderDetails();
            string domain = "";
            string email = "";

            Console.WriteLine("🌐 Initializing ACME Service...");

            while (string.IsNullOrWhiteSpace(domain))
            {
                Console.Write("Enter your domain: ");
                domain = Console.ReadLine();
            }

            while (string.IsNullOrWhiteSpace(email))
            {
                Console.Write("Enter your email: ");
                email = Console.ReadLine();
            }

            try
            {
                var accountSuccess = await acmeService.InitAsync(email);
                if (!accountSuccess)
                {
                    Console.WriteLine("Account creation failed. Please check your email.");
                    return (null, null);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unexpected error during account creation.");
                Console.WriteLine(ex.Message);
                return (null, null);
            }

            try
            {
                 order = await acmeService.BeginOrder(domain);
                if (order.Payload.Status == "invalid")
                {
                    Console.WriteLine("Order is invalid. Please check your domain.");
                    return (null, null);
                }

                Console.WriteLine("✅ Order created successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Order creation failed. Please check your domain.");
                Console.WriteLine(ex.Message);
                return (null, null);
            }

            var dnsChallengeToken = await acmeService.GetDnsChallengeToken(order);




                return (dnsChallengeToken, domain);
        }



        public static async Task CreateCert()
        {

            Console.Clear();
            var acmeService = new AcmeService();
            Console.WriteLine("Creating SSL Certification...");

            //var (dnsChallengeToken, domain) = await acmeService.CreateUserAccountForCert();

            //start testing
            var dnsChallengeToken = Spheressl.GenerateCertRequestId();
            var domain = "www.spherevrf.info"; // Replace with actual domain
            //end testing

            Console.WriteLine($"DNS Challenge Token: \"{dnsChallengeToken}\"");

            Console.WriteLine("Please add the TXT record to your DNS records.\n");

            Console.WriteLine("Press 1: If you need help on what that means.");
            Console.WriteLine("Press 2: Once you have added the record to your DNS");
            Console.WriteLine("Press 3: If you want to exit the program.");

            var choice = Console.ReadLine();
            switch (choice)
            {
                case "1":
                    UI.HowToAddTXTRecord(false);
                    Console.WriteLine("\nPress 2: Once you have added the record to your DNS");
                    break;
                case "2":
                    Console.WriteLine("Verifying DNS record...");

                    await VerifyCertWithSpinner(dnsChallengeToken, domain);
                    break;
                case "3":
                    Environment.Exit(0);
                    break;
                default:
                    Console.WriteLine("Invalid choice. Please try again.");
                    break;
            }

        }


        public static async Task VerifyCert(string dnsChallengeToken, string domain)
        {
            const int maxAttempts = 3;
            int attempt = 0;

            while (attempt < maxAttempts)
            {
                Console.Clear();
                Console.WriteLine($"🔍 Attempting DNS verification (try {attempt + 1} of {maxAttempts})...");
                Console.WriteLine("Verifying DNS record...");

                bool verified = false;

                try
                {
                    verified = await CheckTXTRecordAsync(dnsChallengeToken, domain);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n[ERROR] Verification failed: {ex.Message}");
                    return;
                }

                if (verified)
                {
                    Console.WriteLine("\n🎉 Verification successful! Your cert is being generated...");

                    try
                    {
                        await DownloadCertificateAsync();
                        Console.WriteLine("✅ SSL Certificate created and saved!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Certificate download failed: {ex.Message}");
                    }
                    return;
                }

                Console.WriteLine("\n❌ Verification failed. DNS record not found or incorrect.");
                Console.WriteLine("Make sure the TXT record is saved and includes the quotes!");

                attempt++;

                if (attempt < maxAttempts)
                {
                    Console.WriteLine("\nPress any key to retry verification...");
                    Console.ReadKey();
                }
            }

            Console.WriteLine("\n💥 All attempts failed. Please double-check your DNS settings and try again later.");
        }


        public static async Task VerifyCertWithSpinner(string dnsChallengeToken, string domain)
        {
            const int maxAttempts = 3;
            int attempt = 0;

            while (attempt < maxAttempts)
            {
                Console.Clear();
                Console.WriteLine($"🔍 Attempting DNS verification (try {attempt + 1} of {maxAttempts})...");


                var cts = new CancellationTokenSource();
                var spinnerTask = UI.ShowSpinnerAsync("Verifying DNS record...", cts.Token);

                Task<bool> checkTask = CheckTXTRecordAsync(dnsChallengeToken, domain);
                Task completed = await Task.WhenAny(checkTask, Task.Delay(10000)); // safety timeout just in case

                bool verified = false;

                if (checkTask.IsCompleted)
                {
                    verified = checkTask.Result;
                }

                cts.Cancel(); // stop the spinner
                await spinnerTask; // clean up spinner

                if (verified)
                {
                    Console.WriteLine("\n🎉 Verification successful! Your cert is being generated...");

                    try
                    {
                        await DownloadCertificateAsync();
                        Console.WriteLine("✅ SSL Certificate created and saved!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Certificate download failed: {ex.Message}");
                    }
                    return;
                }

                Console.WriteLine("\n❌ Verification failed. DNS record not found or incorrect.");
                Console.WriteLine($"Make sure the TXT record \"{dnsChallengeToken}\" is saved and includes the quotes!");

                attempt++;

                if (attempt < maxAttempts)
                {
                    Console.WriteLine("\nPress any key to retry verification...");
                    Console.ReadKey();
                }
            }

            Console.WriteLine("\n💥 All attempts failed. Please double-check your DNS settings and try again later.");
        }



        private static async Task DownloadCertificateAsync()
        {
            await Task.Delay(3000);
            Console.WriteLine("\nPDownloaded");
        }

        private static async Task<bool> CheckTXTRecordAsync(string dnsChallengeToken, string domain)
        {
            var lookup = new LookupClient();
            string fullRecordName = $"_acme-challenge.{domain}";

            try
            {
                Console.WriteLine($"🔍 Looking up TXT record{dnsChallengeToken} for {fullRecordName}");
                Console.WriteLine($"At the Location{fullRecordName}");

                var result = await lookup.QueryAsync(fullRecordName, QueryType.TXT);
                var txtRecords = result.Answers.TxtRecords();

                foreach (var record in txtRecords)
                {
                    foreach (var txt in record.Text)
                    {
                        Console.WriteLine($"Found TXT: {txt}");
                        if (txt.Contains(dnsChallengeToken.Trim('"')))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DNS ERROR] {ex.Message}");
            }

            return false; 
        }
    }
}
