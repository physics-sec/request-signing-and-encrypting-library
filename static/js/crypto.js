
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

function fromHexToArr(hex) {
    var arr = new Uint8Array(32);
    for (var i = 0; i < 32; i++) {
        var b = hex.substr(i*2, 2);
        arr[i] = parseInt(b, 16);
    }
    return arr;
}

function wipeArr(arr) {
    for (var i = 0; i < arr.length; i++) {
        arr[i] = 0;
    }
    return arr;
}



async function SHA256(message) {
  var msgUint8 = new TextEncoder().encode(message);                           // encode as (utf-8) Uint8Array
  var hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);           // hash the message
  var hashArray = Array.from(new Uint8Array(hashBuffer));                     // convert buffer to byte array
  var hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
  return hashHex;
}

async function sign_hmac(message, key) {
    var key_ArrayBuffer = fromHexToArr(key);

    var key  = await window.crypto.subtle.importKey(
        "raw",
        key_ArrayBuffer,
        {
            name: "HMAC",
            hash: {name: "SHA-256"},
        },
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["sign", "verify"]
    );
    var enc = new TextEncoder();
    var encoded =  enc.encode(message);
    var signature = await window.crypto.subtle.sign("HMAC", key, encoded);
    var int8Array = new Uint8Array(signature);
    var hexstirng = fromArrToHex(int8Array);
    return hexstirng;
}

async function encryptMessage(message, key) {
    var key_ArrayBuffer = fromHexToArr(key);

    var key  = await window.crypto.subtle.importKey(
        "raw",
        key_ArrayBuffer,
        {
            name: "AES-GCM",
        },
        false,
        ["encrypt", "decrypt"]
    );
    var enc = new TextEncoder();
    var encoded = enc.encode(message);
    // The iv must never be reused with a given key.
    var iv = window.crypto.getRandomValues(new Uint8Array(32));
    var ciphertext = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        key,
        encoded
    );
    var int8Array = new Uint8Array(ciphertext);
    var hexstirng = fromArrToHex(int8Array);
    iv = fromArrToHex(iv);
    return [hexstirng, iv];
}
