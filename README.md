# Understanding DKIM in detail
# Verifying DKIM in by -hand- code

Hey

I recently had problems with my DKIM signature. I just got a 'Signature wrong' message and didn't know what the problem was. So I decided to take a look into.

What is DKIM?
If your mailserver supports DKIM (Domain Keys Identified Mail) it signs the email header and body. So you can be sure that the message was not modified.

# How does it work?
1) Alice writes an email to Bob. No magic is happening in Thunderbird/K-9, ...
2) The email goes to the mail server Alice has configured in her mail client
3) The mailserver does the DKIM magic: It signs the message of Alice (e.g. RSA) and adds the DKIM-Signature header to the mail
4) The mailserver forwards the message to Bob's mailserver
5) Bob's mailserver verifies the DKIM-Signature. Therefore it needs the public key of Alice which it finds in a DNS record
- hier: DMARC oder Thunderbird

# Some more details
This is what the DKIM-Signature looks like:
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=androidloves.me;
    s=2019022801; t=1584218937;
    h=from:from:reply-to:subject:subject:date:date:message-id:message-id:
     to:to:cc:content-type:content-type:
     content-transfer-encoding:content-transfer-encoding;
    bh=aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0=;
    b=eJPHovlwH6mU2kj8rEYF2us6TJwQg0/T7NbJ6A1zHNbVJ5UJjyMOfn+tN3R/oSsBcSDsHT
    xGysZJIRPeXEEcAOPNqUV4PcybFf/5cQDVpKZtY7kj/SdapzeFKCPT+uTYGQp1VMUtWfc1
    SddyAZSw8lHcvkTqWhJKrCU0EoVAsik=

The values are explained RFC6376: https://tools.ietf.org/html/rfc6376#section-3.5
v=1     there is only version 1 right now as far as I know
a=rsa-sha256   alogrithms used for hashing (sha256) and signing (RSA)
c=relaxed/relaxed   Message canonicalization (How is the message prepared before signing?). Values can be simple or relaxed. Specified in https://tools.ietf.org/html/rfc6376#section-3.4
d=androidloves.me domain we will ask for the public key
s=2019022801 selector for the public key. If you have a big mailserver setup and lot of organizational units you want to use multiple keys
t=1584218937 signature Timestamp 
h=from:from:reply-to:subject:subject:date:date:message-id:message-id:to:to:cc:content-type:content-type:content-transfer-encoding:content-transfer-encoding;     signed headers field (headers that are signed, spereated by a colon)
bh=aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0= hash of the canonicalized body. The hash function specified in 'a' is used
b=eJPHovlwH6mU2kj8 ... SddyAZSw8lHcvkTqWhJKrCU0EoVAsik= base64 encoded signature


If we (as a mailserver) receive an email and want to verify wether the email was forged, we first need to get the public key. Therefore we use the s and d paramter out of the DKIM-Signature to construct a DNS request (format is {s}._domainkey.{d} and type TXT)

kmille@linbox ~% dig 2019022801._domainkey.androidloves.me txt +short
"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcaywJn59dbp7TbRiDsVloBdCsgl9wAEvHo9WCDSNRqDJjkF1Fjy44Q4emckHP/Tv7hJdIlBtV8hEw5zGD+/kKkhnlx04BSYqXuxed1nOq6FDjNTIR6TmHetMfVU1IcO7ewyJZp5/2uM64JmTDh2u3ed4+JR7jqFE2e/ZqBTM1iQIDAQAB"

The response is self-explanatory: p is the base64 encoded public key. Now we have just to build the body hash, calculate the signature and compare it with the signature of the DKIM-Signature header (parameter p)


# part 3: Moar detail -vvv

    
    
```python
    mail = email.message_from_bytes(open("email.eml", "rb").read())
    dkim_header = mail.get("DKIM-Signature")

    dkim_parameter = parse_dkim_header(dkim_header)

    {'v': '1',
 'a': 'rsa-sha256',
 'c': 'relaxed/relaxed',
 'd': 'androidloves.me',
 's': '2019022801',
 't': '1584218937',
 'h': 'from:from:reply-to:subject:subject:date:date:message-id:message-id:to:to:cc:content-type:content-type:content-transfer-encoding:content-transfer-encoding',
 'bh': 'aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0=',
 'b': 'eJPHovlwH6mU2kj8rEYF2us6TJwQg0/T7NbJ6A1zHNbVJ5UJjyMOfn+tN3R/oSsBcSDsHTxGysZJIRPeXEEcAOPNqUV4PcybFf/5cQDVpKZtY7kj/SdapzeFKCPT+uTYGQp1VMUtWfc1SddyAZSw8lHcvkTqWhJKrCU0EoVAsik='}
```
