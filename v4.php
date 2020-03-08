<?php
	// https://github.com/chrismeller/awstools
	class AWS_Signature_v4 {

		public function verify ( $sharedKey, $requestId ) {


			// Task 1: Canonical Request
			$canonical_request = array();

			// 1) HTTP method
			$canonical_request[] = $_SERVER['REQUEST_METHOD'];

			// 2) CanonicalURI
			$uri = $_SERVER['REQUEST_URI'];

			// if there is no path, use /
			if ( $uri == '' ) {
				$uri = '/';
			}

			// and URL encode it
			$uri = rawurlencode( $uri );

			// but restore the /'s
			$uri = str_replace( '%2F', '/', $uri );

			$canonical_request[] = $uri;

			// 3) CanonicalQueryString
			$query_string = $_SERVER['QUERY_STRING'];

			$query_string_sorted = array();
			foreach (explode('&', $query_string) as $value) {
				$kv = explode('=', $value);
				$k  = $kv[0];
				$v  = $kv[1];
				// url encode the keys and values
				$query_string_sorted[rawurlencode($k)] = rawurlencode($v);
			}
			// sort the keys
			uksort( $query_string_sorted, 'strcmp' );

			$canonical_query_string = '';

			foreach ($query_string_sorted as $key => $value) {
				$canonical_query_string .= '&' . $key . '=' . $value;
			}
			$canonical_query_string = substr($canonical_query_string, 1); 

			$canonical_request[] = $canonical_query_string;

			// get the signed headers and the signature
			$headers = apache_request_headers();
			$auth_header = $headers['Authorization'];
			$signed_headers = explode("SignedHeaders=", $auth_header)[1];
			$signed_headers_signature = explode(", Signature=", $signed_headers);
			$signed_headers = $signed_headers_signature[0];
			$signed_headers = explode(";", $signed_headers);
			$signature_recived = $signed_headers_signature[1];

			// 4) CanonicalHeaders
			$can_headers = array();
			foreach ( $headers as $k => $v ) {
				if (in_array(strtolower( $k ), $signed_headers)) {
					$can_headers[ strtolower( $k ) ] = trim( $v );
				}
			}

			// sort them
			uksort( $can_headers, 'strcmp' );

			// add them to the string
			foreach ( $can_headers as $k => $v ) {
				$canonical_request[] = $k . ':' . $v;
			}

			// add a blank entry so we end up with an extra line break
			$canonical_request[] = '';

			// 5) SignedHeaders
			$canonical_request[] = implode( ';', array_keys( $can_headers ) );

			// 6) Payload
			$canonical_request[] = hash( "sha256", file_get_contents('php://input') );

			$canonical_request = implode( "\n", $canonical_request );
			error_log( print_r($canonical_request, TRUE) );

			// Task 2: String to Sign
			$string = array();

			// 1) Algorithm
			$string[] = "AWS4-HMAC-SHA256";

			// 4) CanonicalRequest
			$string[] = hash( "sha256", $canonical_request );

			$string = implode( "\n", $string );

			// Task 3: Signature
			$kSigning = hex2bin($sharedKey);
			$signature = hash_hmac( "sha256", $string, $kSigning );

			// check the validity of the signature in a constant-time manner to prevent timing attacks
			$valid = true;
			$length = strlen($signature);
			for ( $i = 0; $i < $length; $i++ ) {
				if ( $signature[$i] !== $signature_recived[$i] ) {
					error_log("signatures do not match!");
					$valid = false;
				}
			}

			if ( $valid === false ) {
				return false;
			}

			if ( $headers["X-Request-Id"] !== $requestId ) {
				error_log("unexpected requestId!");
				return false;
			}

			return true;

		}

		public function getPayload ( $sharedKey ) {
			// check the header to see if the payload is encrypted
			$headers = apache_request_headers();
			if ($headers['X-Payload-Encrypted'] === '0') {
				// if not, just return the payload
				return file_get_contents('php://input');
			}

			// get the ciphertext bytes
			$textToDecrypt = file_get_contents('php://input');
			$encrypted = hex2bin($textToDecrypt);

			// get the key bytes from the signKey
			$key = hex2bin($sharedKey);

			// get the initialization vector bytes from the header
			$iv = $headers['X-IV'];
			$iv = hex2bin($iv);

			// get the authentication tag
			// the WebCryptoAPI adds the tag (of 128 bits by default) at the end of the ciphertext
			$tag_length = 128;
			$tag = substr($encrypted, -($tag_length/8));

			// get ciphertext without tag
			$ciphertext = substr($encrypted,0, strlen($encrypted) - ($tag_length/8));

			// decrypt the ciphertext
			$decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

			// return the platintext
			return $decrypted;
		}
	}
?>
