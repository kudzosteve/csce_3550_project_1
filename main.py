from flask import Flask, request, jsonify
from datetime import datetime, timezone
from KeyManager import KeyGenerator


app = Flask(__name__)       # Flask app
key_gen = KeyGenerator()    # KeyGenerator object


# JWKS server
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    key_gen.del_expired()   # delete expired keys

    valid_keys = [key_gen.get_public_jwk(kid) for kid, key_data in key_gen.keys.items()\
                  if key_data["expiry"] > datetime.now(timezone.utc)
    ]

    if not valid_keys:
        print("[!] No valid keys found in JWKS!")
        key_gen.generate_keys()
        valid_keys = [key_gen.get_public_jwk(kid) for kid, key_data in key_gen.keys.items()\
                      if key_data["expiry"] > datetime.now(timezone.utc)
        ]

    # Return keys in JSON format
    return jsonify({"keys": valid_keys}), 200


# Authentication endpoint
@app.route("/auth", methods=["POST"])
def auth_endpoint():
    # Check if 'expired' query parameter is present
    expired = request.args.get("expired", "false").lower() == "true"
    selected_kid = None # placeholder for the selected kid

    for kid, key_data in key_gen.keys.items():
        print(f"Checking kid: {kid}, Expiry: {key_data['expiry']}")  # Debug print

        # If looking for JWT signed with expired key pair
        if expired and key_data["expiry"] < datetime.now(timezone.utc):
            selected_kid = kid
            break
        # If looking for JWT signed with non-expired key pair
        elif not expired and key_data["expiry"] > datetime.now(timezone.utc):
            selected_kid = kid
            break

    # If no keys are found, return an error
    if not selected_kid:
        return jsonify({"Error": "No valid keys available"}), 404
    selected_kid = key_gen.generate_keys()

    # Generate JSON Web Token
    token = key_gen.create_jwt(selected_kid, expiry=expired)
    return jsonify({"jwt": token})


if __name__ == "__main__":
    key_gen.generate_keys()         # Generate keys
    app.run(port=8080, debug=True)  # Start server