# is-your-domain-in-blocked


https://urlhaus.abuse.ch/api/


To check if a domain or IP is blocked or blacklisted, especially if you're sending high volumes of email, you need to perform several checks. Here's a step-by-step guide to help you determine if a domain is blocked or blacklisted:

### 1. **Check Blacklists**

There are multiple public blacklists that track domains and IP addresses that have been flagged for spam or malicious activities. To check if a domain or IP is listed:

- **DNS-Based Blackhole Lists (DNSBLs)**: Use DNS queries to check if your IP or domain is listed. Common blacklists include:
  - **Spamhaus**: [Spamhaus Lookup](https://www.spamhaus.org/lookup/)
  - **SURBL**: [SURBL Lookup](https://www.surbl.org/surbl-check)
  - **Barracuda**: [Barracuda Lookup](https://www.barracudacentral.org/lookups)
  - **SpamCop**: [SpamCop Lookup](https://www.spamcop.net/w3m?action=checkblock&ip=)

  You can use online tools to perform these lookups or use command-line tools like `dig` or `nslookup`.

### 2. **Check Email Deliverability**

Verify if your emails are being delivered and not landing in spam folders. Tools to check deliverability include:

- **Mail Tester**: [Mail Tester](https://www.mail-tester.com/) – Provides a comprehensive analysis of your email’s spam score and deliverability.
- **GlockApps**: [GlockApps](https://glockapps.com/) – Tests where your email lands (inbox, spam, etc.) across different email providers.

### 3. **Check Domain Reputation**

Assess the reputation of your domain and IP addresses:

- **SenderScore**: [SenderScore](https://www.senderscore.org/) – Provides a score based on the reputation of your sending IP address.
- **Talos Intelligence**: [Talos Intelligence](https://talosintelligence.com/) – Check the reputation of your IP address.

### 4. **Use Email Verification Services**

Services that validate email addresses and domains, ensuring they are not on blacklists and are configured correctly:

- **Hunter.io**: [Hunter.io](https://hunter.io/email-verifier) – Validates emails and checks if they are likely to be delivered.
- **NeverBounce**: [NeverBounce](https://neverbounce.com/) – Checks email addresses for validity and deliverability.

### 5. **Monitor Email Activity**

Keep an eye on your email sending practices:

- **Monitor Bounce Rates**: High bounce rates can indicate issues with your email list or reputation.
- **Monitor Spam Complaints**: High spam complaint rates can affect your reputation and delivery rates.

### Example Code to Check DNSBLs

Here’s a simple Python script to check if an IP address is listed on a DNSBL:

```python
import dns.resolver

def check_dnsbl(ip_address: str, dnsbls: list) -> dict:
    reversed_ip = '.'.join(ip_address.split('.')[::-1])
    results = {}
    
    for dnsbl in dnsbls:
        query = f'{reversed_ip}.{dnsbl}'
        try:
            dns.resolver.resolve(query, 'A')
            results[dnsbl] = 'Listed'
        except dns.resolver.NoAnswer:
            results[dnsbl] = 'Not Listed'
        except dns.resolver.NXDOMAIN:
            results[dnsbl] = 'Domain does not exist'
    
    return results

# Example usage
dnsbls = ['zen.spamhaus.org', 'b.barracudacentral.org', 'bl.spamcop.net']
ip_address = '1.2.3.4'
print(check_dnsbl(ip_address, dnsbls))
```

### Summary

To ensure your emails aren’t landing in spam and your domains/IPs aren’t blacklisted:
- **Check against known blacklists**.
- **Use email deliverability testing tools**.
- **Monitor domain and IP reputation**.
- **Use email verification services**.
- **Monitor your email sending practices** to maintain a good sender reputation.
