#!/usr/bin/env python3

from flask import Flask, render_template, request
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import reqSignWeb
import hashlib
import uuid
import json

app = Flask(__name__)

"""
This is a over simplified backend!
It only supports one session at a time.

The "verifier" object should be unique to each user's session.
"""

verifier = None
verbose_log = True;

@app.route('/')
def home():
	return render_template('index.html')

@app.route('/ecdh', methods=['POST'])
def handshake():
	global verifier
	# This should be done per user!

	# Not the fist handshake
	if verifier != None:
		if verifier.verify(request) is False:
			return "Invalid request."
		# Decrypt the payload
		payload = verifier.getPayload(request)
		js = json.loads(payload, strict=False)
		recived = js['pubkey']
	else:
		# first handshake (not signed)
		# Get the client's public key bytes
		recived = request.json['pubkey']

	if verbose_log:
		print('client\'s public key: ' + recived)

	# Generate a new key pair
	server_keypair = X25519PrivateKey.generate()

	if verbose_log:
		print('server\'s public key: ' + server_keypair.public_key().public_bytes().hex())

	public_bytes = bytes.fromhex(recived)

	# Generate the client's public key object
	peer_public_key = X25519PublicKey.from_public_bytes(public_bytes)

	# Get shared key
	shared_key = server_keypair.exchange(peer_public_key).hex()

	# Pass the shared key through SHA256
	shared_key = hashlib.sha256(shared_key.encode('utf-8')).hexdigest()

	if verbose_log:
		print('shared secret: ' +  shared_key)

	# Get server's public key
	public_key_bytes = server_keypair.public_key().public_bytes().hex()

	# Generate the next request id
	requestId = str(uuid.uuid1())

	if verbose_log:
		print('next request id: ' +  requestId)

	# Generate the verifier object
	verifier = reqSignWeb.reqSignWeb(shared_key, requestId, verbose_log)

	# Delete DH keys from memory
	server_keypair = None
	shared_key = None

	# Send the client the server's public key and the next request id
	return f'{{"pubkey": "{public_key_bytes}", "requestId": "{requestId}"}}'

@app.route('/hello', methods=['POST'])
def hello():

	# Verify that the request is valid
	if verifier.verify(request) is False:
		return "Invalid request."

	# Decrypt the payload
	payload = verifier.getPayload(request)
	js = json.loads(payload, strict=False)
	reflect = js['name']

	# Generate a new request id and update the verifier
	requestId = str(uuid.uuid1())
	verifier.update(requestId)
	if verbose_log:
		print('next request id: ' +  requestId)

	# Send the new request id back to the client
	return f'{{"msg": "hello {reflect}!!", "requestId": "{requestId}"}}'

if __name__ == '__main__':
	app.run(host='0.0.0.0')
