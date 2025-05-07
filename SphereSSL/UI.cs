using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SphereSSL
{
    public class UI
    {
        public static void PrintLogo()
        {
            Console.WriteLine(@"
              ____  ____  _   _ _____ ____  _____  
             / ___||  _ \| | | | ____|  _ \| ____| 
             \___ \| |_) | |_| |  _| | |_) |  _|    
              ___) |  __/|  _  | |___|  _ <| |___   
             |____/|_|   |_| |_|_____|_| \_\_____| 
                        ____  ____  _
                       / ___|/ ___|| |
                       \___ \\___ \| |
                        ___)  ___) | |___
                       |____/|____/\_____|");
        }

        public static void PrintIntroductionScreen()
        {
            PrintLogo();
            Console.WriteLine(@"

SphereSSL is used to create SSL certifications using ACME and Let'sEncrypt
It is not intended to be a full-featured ACME client.
It is intended to be a simple console application that can be used to create
SSL certifications using ACME and Let'sEncrypt.

This app uses DNS-01 challenge to verify domain ownership.
To use this app, you need to have a domain and DNS access.

It's easy to get the SSL certification using DNS-01, but you need to know some basics about domains and DNS.
If you do not know what either of those are or how to get them, please choose Learn More before continuing.

If you don't have a domain, you can use a domain provider like Cloudflare to get one at cost. (about $10 for a .com even less for others).
Avoid using free domains like .tk or .ml as they are often blacklisted by Let's Encrypt.(Their providers can also be shady).

");
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
            Console.Clear();
            PrintMainSelection();
        }

        public static void LearnMore()
        {
            Console.Clear();
            Console.WriteLine("Choose a category To learn more\n");
            Console.WriteLine("1. Domain");
            Console.WriteLine("2. DNS");
            Console.WriteLine("3. SSL");
            Console.WriteLine("4. DNS-01");
            Console.WriteLine("5. How it Works");
            Console.WriteLine("6. Back to Main Menu");

            var choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    WhatIsADomain();
                    break;
                case "2":
                    WhatIsDNS();
                    break;
                case "3":
                    WhatIsSSL();
                    break;
                case "4":
                    WhatIsDNS01();
                    break;
                case "5":
                    HowItWorks();
                    break;
                case "6":
                    Console.Clear();
                   _=Spheressl.MainMenu();
                    break;
            };
        }

        public static void WhatIsADomain(bool learnMore = true)
        {
            if (learnMore)
            {
                Console.Clear();
            }
            Console.WriteLine("What is a Domain?\n");

            Console.WriteLine(@"
A domain is a human-readable address for a website. It is used to identify a specific location on the Internet. 
For example, 'example.com' is a domain so is 'example.org' and 'example.net'. 

Only one person or organization can own a domain at a time. 
When you register a domain, you are essentially renting it for a period of time (usually a year).

If you don't have a domain, you can use a domain provider like Cloudflare to get one at cost. (about $10 for a .com even less for others).
Avoid using free domains like.tk or .ml as they are often blacklisted by Let's Encrypt.(Their providers can also be shady).");


            if (learnMore)
            {
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
                LearnMore();
            }
        }

        public static void WhatIsDNS(bool learnMore = true)
        {
            if (learnMore)
            {
                Console.Clear();
            }
            Console.WriteLine("DNS: Like a GPS for the Internet!\n");

            Console.WriteLine(@"
Okay, so imagine you’re trying to visit your friend’s house, but instead of remembering 
their house’s coordinates, you just remember their name. Easy, right? That’s exactly 
what DNS does for websites.

DNS stands for Domain Name System. When you type a website like 'catsrock.com' into your browser, 
DNS looks up the real address (the IP address) so your device knows where to go.

It’s like asking your phone, 'Take me to Pizza Palace,' and it magically knows the exact location.

When setting up SSL certificates, DNS is super important. You might be asked to add special 
records to your domain’s DNS settings to prove you own the domain.

So yeah, DNS is kinda like your Internet matchmaker. It connects names to addresses.");

            if (learnMore)
            {
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
                LearnMore();
            }
        }

        public static void WhatIsSSL(bool learnMore = true)
        {
            if (learnMore)
            {
                Console.Clear();
            }
            Console.WriteLine("What is SSL?\n");

            Console.WriteLine(@"
SSL stands for Secure Sockets Layer — yeah, it sounds fancy, but it's basically 
a protective bubble for your data when it's flyin' across the Internet.

When a website uses SSL (you'll see 'https://' and a lil' padlock in the address bar), 
it means that the info you send and receive — like passwords, messages, or secret pizza orders — 
is encrypted and safe from eavesdroppers.

Technically, most sites now use TLS (Transport Layer Security), which is like SSL's cooler, 
stronger cousin — but we still say SSL out of habit. Old habits die hard, y'know?

To get SSL on your site, you need a certificate from a trusted authority like Let's Encrypt. 
They’ll check that you own your domain, and boom — secure connection, baby!");
            if (learnMore)
            {
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
                LearnMore();
            }
        }

        public static void WhatIsDNS01(bool learnMore = true)
        {
            if (learnMore)
            {
                Console.Clear();
            }
            Console.WriteLine("What is DNS-01?\n");

            Console.WriteLine(@"
DNS-01 is one of the challenge types used by certificate authorities (like Let's Encrypt) 
to verify that *you* own the domain you're requesting an SSL certificate for.

Instead of clicking a link or uploading a file, the DNS-01 challenge asks you to add a special 
TXT record to your domain's DNS settings. This record contains a verification token 
that proves you're in control of the domain.

Once the record is live, Let's Encrypt (or whoever you're using) checks your DNS zone, 
finds the correct token, and goes: 'Yup, they own it!' — then boom, you’re approved!

DNS-01 is super useful if you're generating a cert for a domain that doesn't have a website 
yet or doesn't support HTTP — or when you're working with wildcard certificates like '*.example.com'.");

            if (learnMore)
            {
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
                LearnMore();
            }
        }

        public static void HowItWorks(bool learnMore = true)
        {
            if (learnMore)
            {
                Console.Clear();
            }
            Console.WriteLine("How This App Works\n");

            Console.WriteLine(@"
This app helps you get a free SSL certificate using the DNS-01 challenge method. 
Here's what you’ll be doing, step-by-step:

1. **Enter your domain and email address**  
   We'll use these to generate a certificate request.

2. **Get a verification token**  
   We’ll talk to the certificate authority (like Let's Encrypt) 
   and get a special token that proves you own the domain.

3. **Add a TXT record to your DNS**  
   - Log into your domain provider (like Cloudflare or Namecheap).  
   - Go to your DNS settings and create a new TXT record.  
   - Set the name (host) to **_acme-challenge.yourdomain.com**  
   - Set the value (content) to the exact token we give you — and yes, include the **quotes** ("" "") around it!

4. **Wait for DNS to propagate**  
   This can take a few seconds to a few minutes. Chill, stretch, vibe.

5. **We verify**  
   Once DNS is updated, we’ll check if the TXT record is correct. 
   If it is — boom! You’re verified.

6. **Get your SSL certificate**  
   If everything checks out, we’ll fetch your certificate files 
   (usually a `.crt` and a `.key`), and you’ll be good to install them!

That’s it! You don't need to be a wizard to get HTTPS — just follow the steps, 
copy the token right, and don't forget those dang quotes!");

            if (learnMore)
            {
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
                LearnMore();
            }
        }

        public static void PrintMainSelection()
        {
            Console.Clear();
            PrintLogo();
            Console.WriteLine("Make a selection.");
            Console.WriteLine("1. Create SSL Certification");
            Console.WriteLine("2. Learn More");
            Console.WriteLine("3. Exit");

        }

        public static void HowToAddTXTRecord(bool learnMore= true)
        {

            if (learnMore)
            {
                Console.Clear();
            }
            Console.WriteLine("How to Add a TXT Record to Your DNS Settings\n");

            Console.WriteLine(@"
Alright, here's how to add the TXT record you'll need for SSL verification (DNS-01 style). 
It’s easy, I promise:

1. **Log in to your domain provider’s website**  
   This could be Cloudflare, Namecheap, GoDaddy, IONOS, etc.

2. **Find your DNS settings**  
   Look for a section called 'DNS', 'DNS Management', or 'DNS Zone Editor'.

3. **Add a new record**  
   - **Type**: TXT  
   - **Name / Host**: `_acme-challenge`  
     (some platforms want the full thing like `_acme-challenge.yourdomain.com`, 
     but most just want `_acme-challenge`)  
   - **Value / Content**: The verification token we gave you — make sure to include the **quotes ("")** around it!  
   - **TTL**: Set to the lowest possible value (like 1 min or Auto) to speed things up.

4. **Save the record**  
   Make sure it shows up in your list of DNS records.

5. **Wait a moment**  
   DNS changes usually update quickly, but it can take a few minutes. 
   We’ll try verifying after a short delay.

Once the record is visible to the certificate authority, you're golden. 
We’ll take it from there and fetch your shiny new cert!");

            if (learnMore)
            {
                Console.WriteLine("Press any key to continue...");
                Console.ReadKey();
                Console.Clear();
                LearnMore();
            }
        }

        public static async Task ShowSpinnerAsync(string message, CancellationToken token)
        {
            var spinner = new[] { "|", "/", "-", "\\" };
            int idx = 0;

            Console.Write($"\n{message} ");

            while (!token.IsCancellationRequested)
            {
                Console.Write(spinner[idx]);
                await Task.Delay(100); // use async delay!
                Console.Write("\b");

                idx = (idx + 1) % spinner.Length;
            }

            Console.Write(" \b");
        }
    }
}
