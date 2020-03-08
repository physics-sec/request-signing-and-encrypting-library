
<?php

	include 'UUID.php';
	include 'v4.php';

	// Comment these lines to hide errors
	//error_reporting(E_ALL);
	//ini_set('display_errors', 1);


	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/backend.php/ecdh') {

		// get the POST data
		$data = json_decode(file_get_contents('php://input'), true);

		// obtain client's public key
		$client_pub_key = $data["pubkey"];
		error_log("client's public key: ". $client_pub_key);
		$client_pub_key = hex2bin($client_pub_key);

		// generate the server's private key
		$secureRandom = random_bytes(32);
		$server_private_key = curve25519_private($secureRandom);

		// obtain the server's public key
		$server_public_key  = curve25519_public($server_private_key);
		$server_public_key  = bin2hex($server_public_key);
		error_log("server's public key: ". $server_public_key);

		// obtain shared key
		$agreement = curve25519_shared($server_private_key, $client_pub_key);
		$agreement = bin2hex($agreement);
		// pass the shared key through SHA256
		$agreement = hash("sha256", $agreement);
		error_log("shared secret: ". $agreement);

		// generate the next request id
		$requestId = UUID::v4();
		$response = '{"pubkey": "'. $server_public_key .'", "requestId": "'. $requestId .'"}';
		header('Content-Type: application/json');

		// save the shared key and the next request Id
		$fp = fopen('creds.txt', 'w');
		fwrite($fp, '{"shared" : "'. $agreement .'", "requestId": "'. $requestId .'"}');
		fclose($fp);

		// return the server's public key and the next request id
		print $response;
		return;
	}

	if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_SERVER['REQUEST_URI'] === '/backend.php') {
		// send the index.html page
		echo readfile("templates/index.html");
		return;
	}

	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/backend.php/hello') {
		// read the shared secret and the next request id from the creds file
		$myfile = fopen("creds.txt", "r") or die("Unable to open file!");
		$creds  = fread($myfile, filesize("creds.txt"));
		fclose($myfile);
		$creds = json_decode($creds, true);

		$shared_key = $creds["shared"];
		$requestId = $creds["requestId"];

		// verify that the request is valid
		$valid = AWS_Signature_v4::verify($shared_key, $requestId);

		if (!$valid) {
			echo "invalid!";
			return;
		}

		// decrypt the payload (don't forget to verify the request first!)
		$msg = AWS_Signature_v4::getPayload($shared_key);
		$msg = json_decode($msg, true);
		$reflect = $msg['name'];

		// generate a new request id
		$requestId = UUID::v4();
		// update the shared secret
		$shared_key = hash("sha256", $shared_key);
		// save the new shared secret and the next request id to the creds file
		$fp = fopen('creds.txt', 'w');
		fwrite($fp, '{"shared" : "'. $shared_key .'", "requestId": "'. $requestId .'"}');
		fclose($fp);

		// send the new request id back to the client
		echo '{"msg": "hello '. $reflect .'!!", "requestId": "'. $requestId .'"}';
		return;
	}
?>
