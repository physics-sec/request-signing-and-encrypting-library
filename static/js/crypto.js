
// Convert an array of bytes to a hex string
function fromArrToHex(arr) {
    var hex = '';
    for (var i = 0; i < arr.length; i++) {
        var b = arr[i].toString(16);
        if (b.length == 1) {
            b = '0' + b;
        } 
        hex += b
    }
    return hex;
}

// Convert a hex string to a array of bytes
function fromHexToArr(hex) {
    var arr = new Uint8Array(32);
    for (var i = 0; i < 32; i++) {
        var b = hex.substr(i*2, 2);
        arr[i] = parseInt(b, 16);
    }
    return arr;
}

// Overwrite all the values of an array to 0x0
function wipeArr(arr) {
    for (var i = 0; i < arr.length; i++) {
        arr[i] = 0;
    }
    return arr;
}

// Get the SHA-256 digest of message
async function SHA256(message) {
    // encode as (utf-8) Uint8Array
    var msgUint8 = new TextEncoder().encode(message);

    // hash the message
    var hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);

    // convert buffer to byte array
    var hashArray = Array.from(new Uint8Array(hashBuffer));

    // convert bytes to hex string
    var hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
}

// Get the HMAC-SHA256 digest of message
async function sign_hmac(message, key) {

    // get the byte array of the key hex string
    var key_ArrayBuffer = fromHexToArr(key);

    // get the key object (from the byte array)
    var key  = await window.crypto.subtle.importKey(
        "raw",
        key_ArrayBuffer,
        {
            name: "HMAC",
            hash: {name: "SHA-256"},
        },
        false,
        ["sign", "verify"]
    );

    // get the encoder
    var enc = new TextEncoder();

    // encode as (utf-8) Uint8Array
    var encoded =  enc.encode(message);

    // sign the encoded message
    var signature = await window.crypto.subtle.sign("HMAC", key, encoded);

    // get the byte array of the signature
    var int8Array = new Uint8Array(signature);

    // get the hex string of the signature
    var hexstirng = fromArrToHex(int8Array);

    return hexstirng;
}

async function encryptMessage(message, key) {
    // get the byte array of the key hex string
    var key_ArrayBuffer = fromHexToArr(key);

    // get the key object (from the byte array)
    var key  = await window.crypto.subtle.importKey(
        "raw",
        key_ArrayBuffer,
        {
            name: "AES-GCM",
        },
        false,
        ["encrypt", "decrypt"]
    );

    // get the encoder
    var enc = new TextEncoder();

    // encode as (utf-8) Uint8Array
    var encoded = enc.encode(message);

    // get 32 random bytes as the initialization vector
    var iv = window.crypto.getRandomValues(new Uint8Array(32));

    // encrypt and get the ciphertext (from the plaintext, the key and the IV)
    var ciphertext = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        key,
        encoded
    );

    // get the byte array of the signature
    var int8Array = new Uint8Array(ciphertext);

    // get the hex string of the ciphertext
    var hexstirng = fromArrToHex(int8Array);

    // get the hex string of the initialization vector
    iv = fromArrToHex(iv);

    // return the ciphertext and the IV
    return [hexstirng, iv];
}
