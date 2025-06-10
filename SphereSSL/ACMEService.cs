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
using System.IO;
using Certes;
using Certes.Pkcs;
using ACMESharp.Crypto.JOSE;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Text;
using Newtonsoft.Json;
using System.Runtime.Intrinsics.Arm;

namespace SphereSSL
{
    public class AcmeService
    {
        private static AcmeProtocolClient _client;
        private static ESJwsTool _signer;
        private static AccountDetails _account;
        private static ServiceDirectory _directory;
        private static OrderDetails _order;
        private static string _domain;
        private static string _challangeDomain;

        public AcmeService()
        {
            _signer = new ESJwsTool();
            _signer.Init();

            var http = new HttpClient
            {
                BaseAddress = new Uri("https://acme-v02.api.letsencrypt.org/")
            };

            _client = new AcmeProtocolClient(http, null, null, _signer);
        }

        public async Task<bool> InitAsync(string email)
        {
            try
            {
                _directory = await _client.GetDirectoryAsync();
                _client.Directory = _directory;

                await _client.GetNonceAsync();
                _account = await _client.CreateAccountAsync(
                     new[] { $"mailto:{email}" },
                     termsOfServiceAgreed: true,
                     externalAccountBinding: null,
                     throwOnExistingAccount: false
                 );

                if (_account == null)
                {
                    Console.WriteLine("Account creation failed._account null.");
                    return false;
                }
                else
                {
                    Console.WriteLine($"Account created successfully. KID: {_account.Kid.ToString()}");


                }


                // Optional log
                Console.WriteLine($"✅ Account created. KID: {_account?.Kid}");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Account creation failed: {ex.Message}");
                Console.WriteLine($"Error- {ex.StackTrace}");
                return false;
            }
        }

        public async Task<OrderDetails> BeginOrder(string domain)
        {
            try
            {

                _client.Account = _account;
                return await _client.CreateOrderAsync(new[] { domain });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Order creation failed: {ex.Message}");
                Console.WriteLine($"Error- {ex.StackTrace}");
                return null;
            }
        }


        //public async Task<string> GetDnsChallengeToken(OrderDetails order)
        //{
        //    var authz = await _client.GetAuthorizationDetailsAsync(order.Payload.Authorizations[0]);
        //    var dnsChallenge = authz.Challenges.First(c => c.Type == "dns-01");

        //    return dnsChallenge.Token;
        //}

        public async Task<(string Domain, string DnsValue)> GetDnsChallengeToken(OrderDetails order)
        {
            var authz = await _client.GetAuthorizationDetailsAsync(order.Payload.Authorizations[0]);
            var dnsChallenge = authz.Challenges.First(c => c.Type == "dns-01");

       
            using SHA256 algor = SHA256.Create();
            var thumbprint = JwsHelper.ComputeThumbprint(_signer, algor);
            var keyAuth = $"{dnsChallenge.Token}.{thumbprint}";
            byte[] hash = algor.ComputeHash(Encoding.UTF8.GetBytes(keyAuth));
            string dnsValue = Base64UrlEncode(hash);

            return (authz.Identifier.Value, dnsValue);
        }

        private static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')                
                .Replace('+', '-')           
                .Replace('/', '_');
        }

        public async Task<(string Token, string Domain)> CreateUserAccountForCert()
        {
            var acmeService = new AcmeService();
            _order = new OrderDetails();
            _domain = "";
     

            string email = "";

            Console.WriteLine("🌐 Initializing ACME Service...");

            while (string.IsNullOrWhiteSpace(_domain))
            {
                Console.Write("Enter your domain: ");
                _domain = Console.ReadLine();
                _domain = "spherevrf.info";
            }

            while (string.IsNullOrWhiteSpace(email))
            {
                Console.Write("Enter your email: ");
                email = Console.ReadLine();
                email = "kl3mta3@gmail.com";
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
                _order = await acmeService.BeginOrder(_domain);
                if (_order.Payload.Status == "invalid")
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

        

            var (domain, dnsValue) = await acmeService.GetDnsChallengeToken(_order);

            return (dnsValue, domain);
        }

        public static async Task CreateCert()
        {

            Console.Clear();
            var acmeService = new AcmeService();
            Console.WriteLine("Creating SSL Certification...");

            var (dnsChallengeToken, domain) = await acmeService.CreateUserAccountForCert();

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
                    break;

                case "2":
                    Console.WriteLine("Waiting 60 seconds before submitting challenge to Let's Encrypt...");
                    await Task.Delay(60000);
                    Console.WriteLine("Verifying DNS record...");
                    await VerifyRecordWithSpinner(dnsChallengeToken, domain);
                    break;

                case "3":
                    Environment.Exit(0);
                    break;

                default:
                    Console.WriteLine("Invalid choice. Please try again.");
                    break;
            }

        }

        public static async Task VerifyRecord(string dnsChallengeToken, string domain)
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
                        Console.WriteLine("\n📡 Submitting challenge to Let's Encrypt...");

                        // Step 1: Get auth URL
                        string authUrl = _order.Payload.Authorizations[0];
                        var authz = await _client.GetAuthorizationDetailsAsync(authUrl);
                        var dnsChallenge = authz.Challenges.First(c => c.Type == "dns-01");

                        // Step 2: Submit the challenge
                        await _client.AnswerChallengeAsync(dnsChallenge.Url);

                        // Step 3: Poll until validated
                        ACMESharp.Protocol.Resources.Authorization updatedAuthz;
                        do
                        {
                            await Task.Delay(2000);
                            updatedAuthz = await _client.GetAuthorizationDetailsAsync(authUrl);
                            Console.WriteLine($"Challenge status: {updatedAuthz.Status}");
                        } while (updatedAuthz.Status == "pending");

                        if (updatedAuthz.Status != "valid")
                        {
                            throw new Exception($"Challenge failed: {updatedAuthz.Status}");
                        }

                        Console.WriteLine("✅ Challenge validated! Finalizing certificate...");

                        // Step 4: Generate CSR (use your key or tool)

                        var key = KeyFactory.NewKey(KeyAlgorithm.RS256);
                        var csrBuilder = new CertificationRequestBuilder(key);
                        csrBuilder.AddName("CN", _domain);
                        csrBuilder.SubjectAlternativeNames.Add(_domain);
                        var csr = csrBuilder.Generate();


                        // Step 5: Finalize order
                        await _client.FinalizeOrderAsync(_order.Payload.Finalize, csr);

                        // Step 6: Wait for cert to be ready
                        OrderDetails finalizedOrder;
                        do
                        {
                            await Task.Delay(2000);
                            finalizedOrder = await _client.GetOrderDetailsAsync(_order.OrderUrl);
                        } while (finalizedOrder.Payload.Status != "valid");

                        // Step 7: Download certificate

                        var certUrl = finalizedOrder.Payload.Certificate;
                        if (string.IsNullOrEmpty(certUrl))
                        {
                            throw new Exception("Certificate URL is missing from the finalized order.");
                        }

                        using var http = new HttpClient();
                        var certPem = await http.GetStringAsync(certUrl);
                        await DownloadCertificateAsync(certPem, key.ToPem());
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Certificate finalization failed: {ex.Message}");
                        return;
                    }

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


        public static async Task VerifyRecordWithSpinner(string dnsChallengeToken, string domain)
        {
            const int maxAttempts = 3;
            int attempt = 0;

            while (attempt < maxAttempts)
            {
                Console.Clear();
                Console.WriteLine($"🔍 Attempting DNS verification (try {attempt + 1} of {maxAttempts})...");


                var cts = new CancellationTokenSource();
                var spinnerTask = UI.ShowSpinnerAsync("Verifying DNS record...", cts.Token);
                bool verified = false;
                try
                {
                    Task<bool> checkTask = CheckTXTRecordAsync(dnsChallengeToken, domain);
                    Task completed = await Task.WhenAny(checkTask, Task.Delay(10000));


                    if (checkTask.IsCompleted)
                    {
                        verified = checkTask.Result;
                    }

                    cts.Cancel(); // stop the spinner
                    await spinnerTask; // clean up spinner
                }
                catch (TaskCanceledException)
                {
                    
                }
                catch (Exception ex)
                {

                    Console.WriteLine($"\n[ERROR] CheckTXTRecordAsync failed: {ex.Message}");
                    return;
                }

                if (verified)
                {
                    // Generate CSR 
                    Console.WriteLine("\n🎉 Pre Verification successful!(The app sees your DNS on your site.) ");
                    var key = KeyFactory.NewKey(KeyAlgorithm.RS256);
                    var csrBuilder = new CertificationRequestBuilder(key);
                    csrBuilder.AddName("CN", _domain);
                    csrBuilder.SubjectAlternativeNames.Add(_domain);
                    var csr = csrBuilder.Generate();

                    try
                    {
                        Console.WriteLine("\n📡 Submitting challenge to Let's Encrypt...");

                        // Step 1: Get auth URL
                        string authUrl = _order.Payload.Authorizations[0];

                        Console.WriteLine($"Auth URL: {authUrl}");
                        var authz = await _client.GetAuthorizationDetailsAsync(authUrl);
                        var dnsChallenge = authz.Challenges.First(c => c.Type == "dns-01");

                        Console.WriteLine($"Expected DNS name: {authz.Identifier.Value}");
                        Console.WriteLine($"Challenge URL: {dnsChallenge.Url}");
                        Console.WriteLine($"Challenge Token: {dnsChallenge.Token}");
                        // Step 2: Submit the challenge
                        await Task.Delay(5000);
                        string challangeDomain = $"_acme-challenge.{_domain}";
                       // dnsChallenge.Url = challangeDomain;
                        await _client.AnswerChallengeAsync(dnsChallenge.Url);

 


                        bool challengeValid = false;
                        for (int i = 0; i < 10; i++)
                        {
                            var auth = await _client.GetAuthorizationDetailsAsync(authUrl);
                            Console.WriteLine($"Challenge status: {auth.Status}");

                            if (auth.Status == "valid")
                            {
                                challengeValid = true;
                                break;
                            }

                            if (auth.Status == "invalid")
                            {
                                Console.WriteLine("❌ Challenge rejected.");
                                return;
                            }

                            await Task.Delay(2000);
                        }

                        if (!challengeValid)
                        {
                            Console.WriteLine("❌ Challenge did not validate in time.");
                            return;
                        }




                        Console.WriteLine("✅ Challenge validated! Finalizing certificate...");


                        // Finalize order
                        int finalizeRetries = 3;
                        int waitBetweenFinalizeMs = 3000;
                        bool finalizeSuccess = false;

                        //Console.WriteLine("🔍 DNS TXT record should exist at:");
                        //Console.WriteLine($"_acme-challenge.{_domain}");
                        //Console.WriteLine($"Expected value: \"{csr}\"");

                        //Console.WriteLine("Pause before submission? [Press any key]");
                        //Console.ReadKey();

                        for (int i = 1; i <= finalizeRetries; i++)
                        {
                            try
                            {
                                Console.WriteLine($"🛠 Finalizing order (Attempt {i}/{finalizeRetries})...");
                                await _client.FinalizeOrderAsync(_order.Payload.Finalize, csr);

                                finalizeSuccess = true;
                                break;
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"❌ Finalize attempt {i} failed: {ex.Message}");
                                await Task.Delay(waitBetweenFinalizeMs);
                            }
                        }


                        if (!finalizeSuccess)
                        {
                            Console.WriteLine("❌ All finalize attempts failed. Please check your order and try again.");
                            Console.WriteLine($"1. Try again?");
                            Console.WriteLine($"2. Restart?");
                            Console.WriteLine($"3. Exit?");

                            string choice = Console.ReadLine();
                            switch (choice)
                            {
                                case "1":

                                    await _client.FinalizeOrderAsync(_order.Payload.Finalize, csr);
                                    return;
                                case "2":
                                    // Exit the program
                                    await Spheressl.MainMenu();
                                    return;
                                default:
                                    Console.WriteLine("Invalid choice. Exiting.");
                                    Environment.Exit(0);
                                    return;
                            }



                        }

                        // Download certificate

                        var certUrl = _order.Payload.Certificate;
                        if (string.IsNullOrEmpty(certUrl))
                        {

                            Console.WriteLine("Certificate URL is missing from the finalized order.");
                            Console.WriteLine("Press any key to start Over.");
                            Console.ReadKey();
                            await Spheressl.MainMenu();

                        }

                        using var http = new HttpClient();
                        var certPem = await http.GetStringAsync(certUrl);
                        await DownloadCertificateAsync(certPem, key.ToPem());


                        Console.WriteLine("✅ SSL Certificate downloaded and saved as cert.pem!");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ERROR] Certificate finalization failed: {ex.Message}");


                    }
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

        public static async Task RequestCertAsync(string domain)
        {
            string authUrl = _order.Payload.Authorizations[0];
            ACMESharp.Protocol.Resources.Authorization authz;
            do
            {
                await Task.Delay(2000);
                authz = await _client.GetAuthorizationDetailsAsync(authUrl);
            } while (authz.Status == "pending");

            if (authz.Status != "valid")
            {
                throw new Exception("DNS challenge failed verification.");
            }
        }

        private static async Task DownloadCertificateAsync(string certPem, string keyPem)
        {
            Console.WriteLine("✅ Certificate is ready!");
            Console.WriteLine("How would you like to save it?");
            Console.WriteLine("1. Separate files (.crt and .key)");
            Console.WriteLine("2. Combined file (.pem with both cert and key)");
            Console.Write("Enter choice (1 or 2): ");
            var fileChoice = Console.ReadLine()?.Trim();

            Console.Write("Enter the folder path to save your certificate files (default: current directory): ");
            var pathChoice = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(pathChoice))
                pathChoice = Directory.GetCurrentDirectory();

            Directory.CreateDirectory(pathChoice); // make sure it exists

            try
            {
                if (fileChoice == "2")
                {
                    // Combined cert + key
                    string combinedPath = Path.Combine(pathChoice, "combined.pem");
                    File.WriteAllText(combinedPath, certPem + "\n" + keyPem);
                    Console.WriteLine($"📄 Saved combined PEM: {combinedPath}");
                }
                else
                {
                    // Separate .crt and .key
                    string certPath = Path.Combine(pathChoice, "certificate.crt");
                    string keyPath = Path.Combine(pathChoice, "private.key");
                    File.WriteAllText(certPath, certPem);
                    File.WriteAllText(keyPath, keyPem);
                    Console.WriteLine($"📄 Saved certificate: {certPath}");
                    Console.WriteLine($"🔐 Saved private key: {keyPath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error saving files: {ex.Message}");
            }

            await Task.Delay(500); // just a little polish
        }

        private static async Task<bool> CheckTXTRecordAsync(string dnsChallengeToken, string domain)
        {
            var lookup = new LookupClient();
            Console.WriteLine($"Domain for Check. {domain}");
            string fullRecordName = $"_acme-challenge.{domain}";

            try
            {
                Console.WriteLine($"🔍 Looking up TXT record {dnsChallengeToken} for {fullRecordName}");
                Console.WriteLine($"At the Location {fullRecordName}");

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
