
<?php

	include 'UUID.php';
	include 'v4.php';

	// Comment these lines to hide errors
	//error_reporting(E_ALL);
	//ini_set('display_errors', 1);


	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/backend.php/ecdh') {
		$data = json_decode(file_get_contents('php://input'), true);

		$client_pub_key = $data["pubkey"];
		error_log("client's public key: ". $client_pub_key);
		$client_pub_key = hex2bin($client_pub_key);

		$secureRandom = random_bytes(32);
		$server_private_key = curve25519_private($secureRandom);

		$server_public_key  = curve25519_public($server_private_key);
		$server_public_key  = bin2hex($server_public_key);
		error_log("server's public key: ". $server_public_key);

		$agreement = curve25519_shared($server_private_key, $client_pub_key);
		$agreement = bin2hex($agreement);
		$agreement = hash("sha256", $agreement);
		error_log("shared secret: ". $agreement);

		$requestId = UUID::v4();
		$response = '{"pubkey": "'. $server_public_key .'", "requestId": "'. $requestId .'"}';
		header('Content-Type: application/json');

		$fp = fopen('creds.txt', 'w');
		fwrite($fp, '{"shared" : "'. $agreement .'", "requestId": "'. $requestId .'"}');
		fclose($fp);

		print $response;
		return;
	}

	if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_SERVER['REQUEST_URI'] === '/backend.php') {
		echo readfile("templates/index.html");
		return;
	}

	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/backend.php/hello') {
		$myfile = fopen("creds.txt", "r") or die("Unable to open file!");
		$creds  = fread($myfile, filesize("creds.txt"));
		fclose($myfile);
		$creds = json_decode($creds, true);

		$shared_key = $creds["shared"];
		$requestId = $creds["requestId"];

		$valid = AWS_Signature_v4::verify($shared_key, $requestId);

		if (!$valid) {
			echo "invalid!";
			return;
		}

		$msg = AWS_Signature_v4::getPayload($shared_key);
		$msg = json_decode($msg, true);
		$reflect = $msg['name'];

		$shared_key = hash("sha256", $shared_key);
		$requestId = UUID::v4();
		$fp = fopen('creds.txt', 'w');
		fwrite($fp, '{"shared" : "'. $shared_key .'", "requestId": "'. $requestId .'"}');
		fclose($fp);

		echo '{"msg": "hello '. $reflect .'!!", "requestId": "'. $requestId .'"}';
		return;
	}
?>
