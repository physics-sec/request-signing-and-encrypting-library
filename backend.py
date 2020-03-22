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
verbose_log = True

@app.route('/')
def home():
	return render_template('index.html')

@app.route('/ecdh', methods=['POST'])
def handshake():
	global verifier
	# This should be done per user!

	# check if it is the first handshake
	if verifier != None:
		# not the fist handshake (signed)

		# verify the signature
		if verifier.verify(request) is False:
			return "Invalid request."

		# decrypt the payload
		payload = verifier.getPayload(request)

		# get the client's public key bytes
		js = json.loads(payload, strict=False)
		recived = js['pubkey']
	else:
		# first handshake (not signed)

		# get the client's public key bytes
		recived = request.json['pubkey']

	if verbose_log:
		print('client\'s public key: ' + recived)

	# generate a new key pair
	server_keypair = X25519PrivateKey.generate()

	if verbose_log:
		print('server\'s public key: ' + server_keypair.public_key().public_bytes().hex())

	# get the bytes from the hex string 
	public_bytes = bytes.fromhex(recived)

	# generate the client's public key object
	peer_public_key = X25519PublicKey.from_public_bytes(public_bytes)

	# get shared key
	shared_key = server_keypair.exchange(peer_public_key).hex()

	# pass the shared key through SHA256
	shared_key = hashlib.sha256(shared_key.encode('utf-8')).hexdigest()

	if verbose_log:
		print('shared secret: ' +  shared_key)

	# get server's public key
	public_key_bytes = server_keypair.public_key().public_bytes().hex()

	# generate the next request id
	requestId = str(uuid.uuid4())

	if verbose_log:
		print('next request id: ' +  requestId)

	# generate the verifier object
	verifier = reqSignWeb.reqSignWeb(shared_key, requestId, verbose_log)

	# delete DH keys from memory
	server_keypair = None
	shared_key = None

	# send the client the server's public key and the next request id
	return f'{{"pubkey": "{public_key_bytes}", "requestId": "{requestId}"}}'

@app.route('/hello', methods=['POST'])
def hello():

	# check that the handshake was performed
	if verifier == None:
		return 'Handshake needed'

	# verify that the request is valid
	if verifier.verify(request) is False:
		return "Invalid request."

	# decrypt the payload (don't forget to verify the request first!)
	payload = verifier.getPayload(request)
	js = json.loads(payload, strict=False)
	reflect = js['name']

	# generate a new request id and update the verifier
	requestId = str(uuid.uuid4())
	# update the shared secret
	shared_key = verifier.signKey
	shared_key = hashlib.sha256(shared_key.encode('utf-8')).hexdigest()
	verifier.update(shared_key, requestId)

	if verbose_log:
		print('next request id: ' +  requestId)

	# send the new request id back to the client
	return f'{{"msg": "hello {reflect}!!", "requestId": "{requestId}"}}'

if __name__ == '__main__':
	app.run(host='0.0.0.0')
