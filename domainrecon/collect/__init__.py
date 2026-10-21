"""
Gathering the facts about a domain, with no AI involved:

    domains       normalising input, reading lists, the registrable domain
    dnsinfo       the DNS resolvers in use, A/AAAA with PTR and ASN, nameservers
    mail          MX records and who runs the mail
    registration  creation date, registrar, expiry (RDAP, whois fallback)
    fingerprint   technologies, favicon hash and CDN (httpx)
    capture       the rendered page: screenshot, HTML, DOM, CSS (Playwright)
    page          page text and an offline language guess
    profile       all of it for one domain, written to a run folder
"""
