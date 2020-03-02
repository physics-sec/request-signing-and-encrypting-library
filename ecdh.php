<?php
	
	// https://github.com/mgp25/curve25519-php
	$client_pub_key = "58a2d7b4e6c775cb1abf8ee88684df1363d124b061ad8efafb5b281a4c41027e";
	$client_pub_key = hex2bin($client_pub_key);

	$secureRandom = random_bytes(32);
	$server_private_key = curve25519_private($secureRandom);
	$server_public_key  = curve25519_public($server_private_key);

	$agreement = curve25519_shared($server_private_key, $client_pub_key);

	$agreement = bin2hex($agreement);

	echo $agreement;

?>

