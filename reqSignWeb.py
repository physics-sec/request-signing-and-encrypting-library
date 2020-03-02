#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib
import re
from urllib.parse import quote, urlparse

class reqSignWeb():
    """
    Class that lets you verify the validity of a request

    Adapted from https://github.com/DavidMuller/aws-requests-auth.git
    """

    def __init__(self,
                 signKey,
                 requestId,
                 verbose_log=False):

        self.signKey = signKey
        self.requestId = requestId
        self.verbose_log = verbose_log

    def update(self,requestId):
        # Update the next request id
        self.requestId = requestId
        # Pass the shared key hex string through SHA256
        self.signKey = hashlib.sha256(self.signKey.encode('utf-8')).hexdigest()

    def getPayload(self, r):
        # check the header to see if the payload is encrypted
        if r.headers.get('X-Payload-Encrypted') == '0':
            # if not, just return the payload
            return r.data

        # get the ciphertext bytes
        ciphertext = bytes.fromhex(r.data.decode('utf-8'))

        # get the key bytes from the signKey
        key = bytes.fromhex(self.signKey)

        # create the AES-GCM object from the key
        aesgcm = AESGCM(key)

        # get the initialization vector bytes from the header
        iv = bytes.fromhex(r.headers.get('X-IV'))

        # decrypt the ciphertext with the AES-GCM object and the IV
        plaintext = aesgcm.decrypt(iv, ciphertext,  None)

        # return the platintext
        return plaintext.decode('utf-8')

    def get_canonical_path(self, r):
        """
        Create canonical URI--the part of the URI from domain to query
        string (use '/' if no path)
        """

        url = r.path
        parsedurl = urlparse(url)

        # safe chars adapted from boto's use of urllib.parse.quote
        # https://github.com/boto/boto/blob/d9e5cfe900e1a58717e393c76a6e3580305f217a/boto/auth.py#L393
        return quote(parsedurl.path if parsedurl.path else '/', safe='/-_.~')

    def get_canonical_querystring(self, r):
        """
        Create the canonical query string. According to AWS, by the
        end of this function our query string values must
        be URL-encoded (space=%20) and the parameters must be sorted
        by name.

        This method assumes that the query params in `r` are *already*
        url encoded.  If they are not url encoded by the time they make
        it to this function, AWS may complain that the signature for your
        request is incorrect.
        """
        canonical_querystring = ''

        url = r.query_string.decode('utf-8')
        parsedurl = urlparse(url)
        querystring_sorted = '&'.join(sorted(parsedurl.query.split('&')))

        for query_param in querystring_sorted.split('&'):
            key_val_split = query_param.split('=', 1)

            key = key_val_split[0]
            if len(key_val_split) > 1:
                val = key_val_split[1]
            else:
                val = ''

            if key:
                if canonical_querystring:
                    canonical_querystring += "&"
                canonical_querystring += u'='.join([key, val])

        return canonical_querystring

    def verify(self, r):

        canonical_uri = self.get_canonical_path(r)

        canonical_querystring = self.get_canonical_querystring(r)

        header = r.headers.get('Authorization')

        signed_headers = header.split('SignedHeaders=')[1]

        signed_headers = signed_headers.split(', Signature')[0]

        canonical_headers = ''
        for s_header in signed_headers.split(';'):
            for header, val in r.headers:
                if header.lower() == s_header:
                    # Remove content-type parameters as some browser might change them on send
                    if s_header == 'content-type':
                        val = val.split(';')[0]
                    canonical_headers += s_header + ':' + val + '\n'
                    break

        body = r.data
        if body == '':
            body = None
        body = body if body else bytes()

        payload_hash = hashlib.sha256(body).hexdigest()

        # Combine elements to create create canonical request
        method = r.method
        canonical_request = (method + '\n' + canonical_uri + '\n' +
                             canonical_querystring + '\n' + canonical_headers +
                             '\n' + signed_headers + '\n' + payload_hash)

        algorithm = 'AWS4-HMAC-SHA256'
        if self.verbose_log:
            print('canonical request:\n' +  canonical_request)

        string_to_sign = (algorithm + '\n' + hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

        signing_key = bytes.fromhex(self.signKey)

        # Sign the string_to_sign using the signing_key
        string_to_sign_utf8 = string_to_sign.encode('utf-8')
        signature = hmac.new(signing_key,
                             string_to_sign_utf8,
                             hashlib.sha256).hexdigest()

        received_signature = r.headers.get('Authorization').split('Signature=')[1]

        if len(received_signature) != 64:
            print('invalid signature length')
            return False

        # check the validity of the signature in a constant-time manner to prevent timing attacks
        valid = True
        for i in range(64):
            if signature[i] != received_signature[i]:
                valid = False
        if valid is False:
            print(f'signatures do not match!')
            return False

        # get the requestId from the header
        received_requestId = r.headers.get('X-Request-Id')

        # check that the request ids are equal to prevent replay attacks
        if received_requestId != self.requestId:
            print('unexpected requestId!')
            return False

        return True
