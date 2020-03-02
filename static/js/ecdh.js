

window.verbose_log = true;

async function ecdh_handshake(){

    var array = new Uint8Array(32);

    // generate the private key
    var rand = window.crypto.getRandomValues(array);

    // generate the key pair
    var keypair = axlsign.generateKeyPair(rand);

    // get the public key
    var pubkey = fromArrToHex(keypair.public);
    if (window.verbose_log) {
        console.log('client\'s public key: ' + pubkey);
    }

    var request = {
        method: 'POST',
        url: '/ecdh',
        headers: {
            'Content-Type': 'application/json'
        },
        data: '{"pubkey": "' + pubkey + '"}'
    };

    if (typeof window.signer !== "undefined") {
        request = await signer.sign(request);
    }

    // send the public key to the server
    fetch(request.url, {
      method: request.method,
      body: request.data,
      headers: request.headers
    })
    .then((response) => response.json())
    .then(async (data) => {

        // get the server's public key bytes
        var serverKey = data["pubkey"];
        if (window.verbose_log) {
            console.log('server\'s public key: ' + serverKey);
        }

        // get the next request id
        window.requestId = data["requestId"];
        if (window.verbose_log) {
            console.log('next request id: ' + window.requestId);
        }

        // generate the client's public array
        var server_pubkey = fromHexToArr(serverKey);

        // get shared key bytes
        var sharedSecret = axlsign.sharedKey(keypair.private, server_pubkey);

        // get the shared key hex string
        var hexstring = fromArrToHex(sharedSecret);

        // pass the shared key hex string through SHA256
        window.shared_secret = await SHA256(hexstring);
        if (window.verbose_log) {
            console.log('shared secret: ' + window.shared_secret)
        }

        // create the cofig object of the signer
        var config = {
            signKey: window.shared_secret,
            requestId: window.requestId,
        };

        // generate the signer object
        window.signer = new reqSignWeb.ReqSigner(config);

        // delete DH keys from memory (not really necessary)
        array = wipeArr(array);
        rand = wipeArr(rand);
        sharedSecret = undefined;
        hexstring = undefined;
        keypair.private = wipeArr(keypair.private);
        keypair = undefined;

    })
    .catch((error) => {
      console.error('Error:', error);
    });

    // re-do the handshake at random invervals (between 3 and 10 minutes)
    var min = 3;
    var max = 10;
    min *= 60000;
    max *= 60000;

    // get the next random interval
    var rand = Math.floor(Math.random() * (max - min + 1) + min);

    // wait for 'rand' time to re-do the handshake
    setTimeout(ecdh_handshake, rand);
}

// make the first handshake
ecdh_handshake();
