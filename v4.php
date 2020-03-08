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

			$canonical_request[] = $uri;		// 2) URI

			// 3) CanonicalQueryString
			$canonical_request[] = $_SERVER['QUERY_STRING'];

			$headers = apache_request_headers();
			$auth_header = $headers['Authorization'];
			$signed_headers = explode("SignedHeaders=", $auth_header)[1];
			$signed_headers_signature = explode(", Signature=", $signed_headers);
			$signed_headers = $signed_headers_signature[0];
			$signed_headers = explode(";", $signed_headers);
			$signature_recived = $signed_headers_signature[1];

			// 4) CanonicalHeaders
			$can_headers = array();
			foreach ( apache_request_headers() as $k => $v ) {
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

			$valid = true;
			$length = strlen($signature);
			for ( $i = 0; $i < $length; $i++ ) {
				if ( $signature[$i] !== $signature_recived[$i] ) {
					$valid = false;
				}
			}

			if ( $valid === false ) {
				return false;
			}

			if ( $headers["X-Request-Id"] !== $requestId ) {
				return false;
			}

			return true;

		}

		public function getPayload ( $sharedKey ) {
			$textToDecrypt = file_get_contents('php://input');
			$encrypted = hex2bin($textToDecrypt);

			$key = hex2bin($sharedKey);

			$headers = apache_request_headers();
			$iv = $headers['X-IV'];
			$iv = hex2bin($iv);

			// the WebCryptoAPI adds the tag (of 128 bits by default) at the end of the ciphertext
			$tag_length = 128;
			$tag = substr($encrypted, -($tag_length/8));

			$ciphertext = substr($encrypted,0, strlen($encrypted) - ($tag_length/8));

			$decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

			return $decrypted;
		}
	}
?>
