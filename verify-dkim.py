#!/usr/bin/env python3
from typing import Dict, Optional
import re
import sys
from base64 import b64encode, b64decode
import email
import email.message
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence, DerNull, DerOctetString, DerObjectId
import Crypto.Util
from Crypto.Util.number import bytes_to_long, long_to_bytes
import dns.resolver


def hash_body(body: str) -> str:
    # https://tools.ietf.org/html/rfc6376#section-3.4.4
    # body canonicalization as specified in https://tools.ietf.org/html/rfc6376#section-3.4.4
    # this code is not RFC compliant. It misses for example:
    # ** Reduce all sequences of WSP within a line to a single SP ** 
    canonicalized_body = body.strip().encode() + b"\r\n"
    bh = b64encode(SHA256.new(canonicalized_body).digest())
    assert bh == b'aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0='
    return bh.decode()


def get_public_key(domain: str, selector: str) -> RSA.RsaKey:
    dns_response = dns.resolver.query("{}._domainkey.{}.".format(selector, domain), "TXT").response.answer[0].to_text()
    p = re.search(r'p=([\w\d/+]*)', dns_response).group(1)
    pub_key = RSA.importKey(b64decode(p))
    assert pub_key.e == 65537
    assert pub_key.n == 109840904909940404959744221876858620709969218326506407082221779394032326489812790786649034812718574099046117725854400828455845069780702401414898758049907995661494814186559221483509803472525659208951140463116595200877740816407104014421586827141402457631883375757223612729692148186236929622346251839432830432649
    return pub_key


def parse_dkim_header(dkim_header: str) -> Dict[str, str]:
    """
    dkim_header: DKIM-Signature header from the mail as str
        v=1; a=rsa-sha256; c=relaxed/relaxed; d=androidloves.me;
        s=2019022801; t=1584218937;
        h=from:from:reply-to:subject:subject:date:date:message-id:message-id:
         to:to:cc:content-type:content-type:
         content-transfer-encoding:content-transfer-encoding;
        bh=aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0=;
        b=eJPHovlwH6mU2kj8rEYF2us6TJwQg0/T7NbJ6A1zHNbVJ5UJjyMOfn+tN3R/oSsBcSDsHT
        xGysZJIRPeXEEcAOPNqUV4PcybFf/5cQDVpKZtY7kj/SdapzeFKCPT+uTYGQp1VMUtWfc1
        SddyAZSw8lHcvkTqWhJKrCU0EoVAsik=

    return: Dict of parsed DKIM-Signature header
        {'v': '1',
         'a': 'rsa-sha256',
         'c': 'relaxed/relaxed',
         'd': 'androidloves.me',
         's': '2019022801',
         't': '1584218937',
         'h': 'from:from:reply-to:subject:subject:date:date:message-id:message-id:to:to:cc:content-type:content-type:content-transfer-encoding:content-transfer-encoding',
         'bh': 'aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0=',
         'b': 'eJPHovlwH6mU2kj8rEYF2us6TJwQg0/T7NbJ6A1zHNbVJ5UJjyMOfn+tN3R/oSsBcSDsHTxGysZJIRPeXEEcAOPNqUV4PcybFf/5cQDVpKZtY7kj/SdapzeFKCPT+uTYGQp1VMUtWfc1SddyAZSw8lHcvkTqWhJKrCU0EoVAsik='
        }
    """
    parameter = {}
    parts = dkim_header.split(";")
    for part in parts:
        key, value = part.split("=", 1)
        parameter[key.strip()] = re.sub(r'(\n|\t\|\r|\s)', "", value)
    return parameter


def hash_headers(mail: email.message.Message, header_to_hash: str, bh: str) -> SHA256.SHA256Hash:
    # mail: email.message.Message object
    # header_to_hash: list of email headers to hash seperated by a colon
    # bh: body hash of the email body base64 encoded
    #
    # in:  'from:from:reply-to:subject:subject:date:date:message-id:message-id:to:to:cc:content-type:content-type:content-transfer-encoding:content-transfer-encoding'
    # build "from:Christian Schneider <christian.schneider@androidloves.me>\r\n..."
    #

    header_to_hash_list = header_to_hash.split(":")
    headers = ""

    for header in header_to_hash_list:
        if mail[header] and header in header_to_hash_list:
            headers += header.lower() + ":" + mail[header].strip() + "\r\n"
            header_to_hash_list.remove(header) # strip duplicate header like the from

    dkim_header = mail.get("DKIM-Signature")
    dkim_header = re.sub(r'(\n|\r)', "", dkim_header)
    dkim_header = re.sub(r'\s+', " ", dkim_header)
    headers += "dkim-signature:{}\r\n".format(dkim_header)
    headers = re.sub(r'b=[\w0-9\s/+=]+', "b=", headers) #replace b=... with be=

    hheader = SHA256.new(headers.encode())
    assert hheader.hexdigest() == "5188ff42a5ab71ae70236cf66822ab963b0977a3e7d932237fbfc35005195720"
    return hheader


def pkcs1_v1_5_encode(msg_hash: SHA256.SHA256Hash, emLen: int) -> bytes:
    # this code is copied from  EMSA_PKCS1_V1_5_ENCODE
    # https://github.com/dlitz/pycrypto/blob/v2.7a1/lib/Crypto/Signature/PKCS1_v1_5.py#L173
    digestAlgo = DerSequence([ DerObjectId(msg_hash.oid).encode() ])

    #if with_hash_parameters:
    if True:
        digestAlgo.append(DerNull().encode())

    digest      = DerOctetString(msg_hash.digest())
    digestInfo  = DerSequence([
                    digestAlgo.encode(),
                      digest.encode()
                    ]).encode()

    # We need at least 11 bytes for the remaining data: 3 fixed bytes and
    # at least 8 bytes of padding).
    if emLen<len(digestInfo)+11:
          raise TypeError("Selected hash algorith has a too long digest (%d bytes)." % len(digest))
    PS = b'\xFF' * (emLen - len(digestInfo) - 3)
    return b'\x00\x01' + PS + b'\x00' + digestInfo


def verify_signature(hashed_header: SHA256.SHA256Hash, signature: bytes, public_key: RSA.RsaKey) -> bool:
    modBits = Crypto.Util.number.size(public_key.n)
    emLen = modBits // 8

    signature_long = bytes_to_long(signature)
    expected_message_int = pow(signature_long, public_key.e, public_key.n)
    expected_message = long_to_bytes(expected_message_int, emLen)

    padded_hash = pkcs1_v1_5_encode(hashed_header, emLen)

    assert padded_hash == expected_message
    return padded_hash == expected_message


if __name__ == '__main__':
    mail = email.message_from_bytes(open("email.eml", "rb").read())
    dkim_header = mail.get("DKIM-Signature")

    dkim_parameter = parse_dkim_header(dkim_header)

    body = mail.get_payload()
    body_hash = hash_body(body)

    if body_hash == dkim_parameter['bh']:
        print("body hash matches")
    else:
        print(f"body hash mismatch. Got {body_hash} - expected {dkim_parameter['bh']}")
        sys.exit(1)

    public_key = get_public_key(dkim_parameter['d'], dkim_parameter['s'])
    hashed_header = hash_headers(mail, dkim_parameter['h'], body_hash)

    signature = b64decode(dkim_parameter['b'])

    if verify_signature(hashed_header, signature, public_key):
        print("signature is valid")
    else:
        print("signature is NOOOOT valid")
    print("done")



