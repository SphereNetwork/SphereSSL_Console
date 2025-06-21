# 🌐 SphereSSL - SSL Made Easy

## Overview

**SphereSSL** is a lightweight console app that simplifies the process of generating **Let's Encrypt SSL certificates** using the **DNS-01 challenge** method.

No wild configs. Just clean, user-friendly SSL magic in your terminal.  
Perfect for devs who need certificates fast, without wrestling a yak in a cloud CLI.

---

## Features

- Interactive menu and beginner-friendly prompts
- Educational walkthroughs for domain, DNS, SSL, and DNS-01
- Uses Let's Encrypt via the ACME protocol
- Supports wildcard certs via DNS-01 challenge
- Handles DNS record verification with fallback to multiple resolvers (Google, Cloudflare, OpenDNS, Quad9)
- Automatically downloads and saves certs as `.crt`, `.key`, or combined `.pem`
- Windows Explorer auto-opens cert folder upon success

---

## Prerequisites

- .NET 6 or higher installed
- A registered domain name
- Access to your DNS provider (e.g., Cloudflare, Namecheap, GoDaddy)
- Ability to add **TXT records** to your domain's DNS zone

---

## Getting Started

1. **Clone the repo:**

    ```bash
    git clone https://github.com/kl3mta3/SphereSSL.git
    cd SphereSSL
    ```

2. **Build the project:**

    ```bash
    dotnet build
    ```

3. **Run the app:**

    ```bash
    dotnet run
    ```

---

## Usage Flow

### Main Menu

```text
1. Create SSL Certification
2. Learn More
3. Exit
```

### Learn Mode

Detailed mini-guides on:

- What is a Domain?
- What is DNS?
- What is SSL?
- What is DNS-01?
- Step-by-step How it Works

### Create Certificate

1. Enter domain + email
2. Get DNS-01 token
3. Add TXT record to DNS: `_acme-challenge.yourdomain.com`
4. App verifies propagation (auto retries)
5. Challenge validated
6. Certificate downloaded 

---

## Output Files

Certs are saved to the folder of your choice, defaulting to:

```
./certs/
```

With naming format like:

- `cert_YYYYMMDD_HHmmss_certificate.crt`
- `cert_YYYYMMDD_HHmmss_private.key`
- `cert_YYYYMMDD_HHmmss_combined.pem`

---

## Structure

| File               | Purpose                                          |
|--------------------|--------------------------------------------------|
| `Program.cs`       | Entry point — kicks off main menu               |
| `UI.cs`            | Handles UI, intro screen, help content, footer  |
| `Spheressl.cs`     | Controls flow logic, input prompts              |
| `ACMEService.cs`   | Handles Let's Encrypt logic, DNS verification, cert download |

---

## Pro Tips

- TXT record values **must include quotes** (`"like-this"`).
- DNS propagation can take time — don't panic if it takes a few minutes.
- Avoid free TLDs like `.tk` or `.ml` — they're often blocked by Let's Encrypt.
- When in doubt, hit "Learn More" from the menu.



---

## License

MIT License

> Built with caffeine, dark humor, and a DNS obsession.

---

## Aesthetic Preview

```
 ____  ____  _   _ _____ ____  _____  
/ ___||  _ \| | | | ____|  _ \| ____| 
\___ \| |_) | |_| |  _| | |_) |  _|    
 ___) |  __/|  _  | |___|  _ <| |___   
|____/|_|   |_| |_|_____|_| \_\_____| 

        SSL Made Easy
```

---

## -Kenneth Lasyone ©2025
