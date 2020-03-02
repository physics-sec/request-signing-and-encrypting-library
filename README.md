
# request-signing-and-encrypting-library

This project presents a very simple webpage that signs and encrypts the requests sent from the client to the server.  

It uses **Elliptic-curve Diffie-Hellman** (with curve25519) to generate a shared secret and then signs all the requests with a modified version of the **AWS v4 signature scheme**.  
If the request is a POST, then it encrypts the payload with **AES-GCM**.

The main idea is to present an easy-to-implement way of signing and encrypting requests.  


## Key generation
Each time a user enters the page, the server and the client perform a (Elliptic curve based) Diffie Hellman key exchange.  
Meaning, they generate ECDH key-pair and then exchange public keys in order to calculate the same shared secret.  
Once they have the same secret, they pass the hex string of the key through SHA256 and then use the result for request signing AND encrypting (the same key is used for both).  
Every time a request is signed and  encrypted, the key passes through SHA256 again.  

At random intervals, the client will re-do the handshake with the server and get a new shared key, this is mostly done for post-compromise recovery.


## Signature scheme: Differences with AWS v4
#### SignKey generation
The region, service, accessKeyId and secretAccessKey are not longer used to generate the signKey.  
This signKey is generated as stated above.  


#### Removed headers
The x-amz-date header is not longer used.

#### Added headers
The x-request-id header has been added.  
This header is nothing more than a UUID, it protects the server from replay attacks. 
The server provides a new UUID in every reply, and expects to receive it back in the next request.  
If the same request is received twice, the second one will be ignored because the UUIDs will not match.

#### Authorization header
The Authorization header no longer contains the "Credential" part as it is no longer needed.

The original Authorization header looked like:  
`Authorization: AWS4-HMAC-SHA256 Credential=ASIAIQTP2FX4MJ4J2DIA/20160520/eu-west-1/execute-api/aws4_request, SignedHeaders=accept;host;x-amz-date, Signature=cc870c6ea5174baad470e46a7f5642725ff9411e049cf24d730923fca7e5f2b4`

Now it looks like the following:  
`Authorization: AWS4-HMAC-SHA256 SignedHeaders=accept;content-type;header1;host;x-request-id, Signature=ad3f3bfb9ba8a5a8149554be61a1f8c1873c2bac5a57d3129ed58f56e5d18b1e`  


## Encryption
As previously said, encryption is performed with AES in GCM mode.  
The key used for encrypting is obtain in the **Key generation** section.  
The IV is generated by the client. It consists of 32 random bytes.  
The server obtains the IV via the `X-IV` header.  
The client indicates the server that the payload is encrypted with the `X-Payload-Encrypted` header.

Sample of a request signed and encrypted:

```
POST /path?foo=bar
Host: domain.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0
Accept: application/json
Accept-Language: en,de-DE;q=0.8,en-US;q=0.5,es;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://0.0.0.0:5000/
X-IV: 3b7b4f06187ee710dd98e379aaa800e028196dcdf0d3fc328ba703274469952b
X-Payload-Encrypted: 1
Content-Type: text/plain
Authorization: AWS4-HMAC-SHA256 SignedHeaders=accept;content-type;host;x-iv;x-payload-encrypted;x-request-id, Signature=bf2c0b9c42fbc024f62ddac8388b22b3bd4bd5f6f56a2a845c033dadea2b1874
X-Request-Id: fd7ee876-5c13-11ea-b642-50eb7158b862
Origin: https://domain.com
Content-Length: 62
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache

4df2ecc1283981ca21984f8809c2389793d481ed154c179cc78a90e04d80fb
```

## Webpage example

The web page is written in HTML and JavaScript, the backend is written in Python3.

Feel free to clone the repository and play with the requests in Burp.

### Instalation

Simply clone the repository:
```
git clone https://github.com/physics-sp/request-signing-implementation.git
```
Run the web server:
```
cd request-signing-implementation
python3 backend.py
```
And visit the webpage: `http://127.0.0.1:5000/`


## What is it NOT for
This is **NOT** a replacement for HTTPS.
This type of cryptography can't and won't protect you from man in the middle attacks.  
This is because there is no authentication provided, meaning that you don't know for sure you are talking to the server and not an attacker. 

This kind of protections are **NOT** a replacement for server-side validation.  
Every input received from the user **MUST** be checked by the server before further processing.


## What is it for
This implementation will help you prevent CSRF attacks (for the request that are signed).  

It will also make exploiting XSS vulnerabilities more challenging (but not impossible).  

The main benefit, in my opinion, is that it makes it much harder for an attacker to tamper with the requests and find vulnerabilities in the backend server.  
Especially while using automated tools such as SQLMap.

An experienced attacker will certainly be able to bypass this type of protections.  

This is mostly a learning experience, but this type of protections *should* be easy to implement, but now a days there are no great libraries that implement these type of cryptography.  
This is a small contribution into making this protections easier to implement.


## Considerations
A real implementation of this library, should take into account that each session will have two values associated with the cookie(s): the shared key and the next request id.  

The next request id should change in every request (obviously), and the shared key should ideally change over time.  
This is currently done by passing the key through SHA256 every time is used and by performing additional Diffie Hellman key exchanges at random intervals.  

After a DH keypair is used to get a shared secret, it should be discarded and forgotten (to provide forward secrecy).

If you are planning to use a backend other than Python, take into account that there are some ECDH libraries that are not compatible with the JavaScript library, this is because some libraries represent the private/public keys in different ways.
The library you choose should encode their keys acoding to the [X25519 RFC](https://tools.ietf.org/html/rfc7748).


## How to implement

### Fronend
First, import all the important scripts
```html
<script src="static/js/crypto.js"></script>
<script src="static/js/web-request-signing.js"></script>
<script src="static/js/axlsign.js"></script>
<script src="static/js/ecdh.js"></script>
```

When you want to send a request, do as follows:
```javascript
// create the resquest
var request = {
    method: 'POST',
    url: '/some/path',
    params: {
        'a': 'val1',
        'c': 'val2',
        'b': 'val3'
    },
    headers: {
        'Content-Type': 'application/json',
        'X-Test': 'headerTest123'
    },
    data: '{"foo": "bar"}'
};
// sign the request
var request = await signer.sign(request);
// make the request
fetch(request.url, {
    method: request.method,
    headers: request.headers,
    body: request.data,
})
```

If you make the request inside a function, you will have to add the *async* keyword before the function declaration.  
Like so:
```javascript
async function func () {
    // code
}
```


### Backend
The only backend supported right now is Python 3.  
All you need to do is implement the handshake method when you receive a POST request to /ecdh.  

Import the request validator:
```python
import reqSignWeb
```

When receiving a normal request, validate it as follows:
```python
# create the verifier with the shared_key and requestId of the current session.
verifier = reqSignWeb.reqSignWeb(shared_key, requestId)
# verify that the request is valid
if verifier.verify(request) is False:
        # request is invalid, return an error
        return "Invalid request."
# request is valid, proceed as normal
```

When the request has a payload, decrypt it as follows:
```python
payload = verifier.getPayload(request)
```

Then creating the response, generate a new requestId, update the verifier and send the new requestId to the client.
```python
# generate a new request id
requestId = str(uuid.uuid1())
# update the verifier (or just save the new requestId into a database)
verifier.update(requestId)
# send the new request id back to the client
return f'{{"foo": "bar", "requestId": "{requestId}"}}'
```
In this example, there is only one verifier object, in a real implementation, the current requestId and signKey of each active session should be stored in a database.  
When a request is received, the requestId and signKey of the session should be retrieved and the verifier object should be instantiated with these values.  

## Credit

Several projects where used to obtain some of the core logic (some have been modified):

### AWS v4
- https://github.com/danieljoos/aws-sign-web  (JavaScript)
- https://github.com/DavidMuller/aws-requests-auth (Python)

### ECDH with curve25519
- https://github.com/wavesplatform/curve25519-js (JavaScript)
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/ (Python)



## Ideas for the future
- Replace the JavaSCript ECDH logic with a well supported library.
- Encrypt (and sign?) responses from the server.
- Use different keys for signing and encrypting.
- Add backend implemented in PHP, Node and/or Java.
