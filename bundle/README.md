# Example bundle for Encrypted JWT Callout

This directory contains is an example API Proxy bundle that demonstrates the
Encrypted-JWT Java calout. The callout can generate and verify JWT and JWE, that
use the `RSA-OAEP-256` key encryption algorithm.

## Pre-requisites

1. Deploy the API Proxy into an Apigee organization + environment.

## Invoke it

1. generate an example encrypted JWT
   ```
   $endpoint=https://foo.bar.com
   curl -i ${endpoint}/encrypted-jwt-java/generate_jwt -d ''
   ```

   You should see something like this as output:
   ```
   HTTP/2 200
   content-type: text/plain
   content-length: 755
   date: Mon, 16 Nov 2020 19:28:59 GMT
   server: apigee
   via: 1.1 google
   alt-svc: clear

   eyJ0eXAiOiJKV1Q....eXX258QmzYdBA
   ```

2. verify an example encrypted JWT:

   ```
   JWT=eyJ0eXAiOiJKV1Q....eXX258QmzYdBA (from above)
   curl -i ${endpoint}/encrypted-jwt-java/verify_jwt -d "JWT=${JWT}"

   ```

   For a valid JWT, you should see something like this:
   ```
   HTTP/2 200
   content-type: application/json
   content-length: 308
   date: Mon, 16 Nov 2020 20:38:02 GMT
   server: apigee
   via: 1.1 google
   alt-svc: clear

   {
     "header": {"typ":"JWT","enc":"A256GCM","alg":"RSA-OAEP-256"},
     "payload": {"sub":"dino@apigee.com",...,"exp":...,"iat":...,"jti":"..."}
   }
   ```

3. generate an example JWE (not a JSON payload)
   ```
   curl -i ${endpoint}/encrypted-jwt-java/generate_jwe -d ''
   ```

   You should see something like this as output:
   ```
   HTTP/2 200
   content-type: text/plain
   content-length: 473
   date: Mon, 16 Nov 2020 20:39:35 GMT
   server: apigee
   via: 1.1 google
   alt-svc: clear

   eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.PelZ...ZYBiXy85u.ZkjuSBvcW7iU4vj6oOo9KA

   ```

4. verify the example JWE

   ```
   JWE=eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.PelZ...ZYBiXy85u.ZkjuSBvcW7iU4vj6oOo9KA
   curl -i ${endpoint}/encrypted-jwt-java/verify_jwe -d "JWE=${JWE}"
   ```
   You should see output that looks something like this:
   ```
   HTTP/2 200
   content-type: application/json
   content-length: 165
   date: Mon, 16 Nov 2020 21:26:08 GMT
   server: apigee
   via: 1.1 google
   alt-svc: clear

   {
     "header": {"enc":"A256GCM","alg":"RSA-OAEP-256"},
     "payload": "Arbitrary-string-to-encrypt,messageid=f363c1b8-ed31-48d3-8b30-eff4a7198907,time=1605561141276"
   }

   ```

5. Generate an encrypted JWT using a JWKS as a source for the key
   This logic randomly chooses an RS256 key from the JWKS and uses that. It embeds the
   keyid into the JWT header.
   ```
   curl -i $endpoint/encrypted-jwt-java/generate_jwt_via_jwks -d ''
   ```

6. Likewise, you can generate a JWE using JWKS as the source for the public key.
   ```
   curl -i $endpoint/encrypted-jwt-java/generate_jwe_via_jwks -d ''
   ```


7. Generate a signed JWT, then encrypt it:
   ```
   curl -i https://5g-dev.dinochiesa.net/encrypted-jwt-java/signed_jwt_wrapped_in_jwe -d ''
   ```




## Interoperating with other systems

You can use the `/generate_jwt` endpoint to encrypt a JWT, and then use an
external system to decrypt it (For example, https://dinochiesa.github.io/jwt).
Likewise with `/generate_jwe`.  To decrypt, you will need to provide the private
key to the external system.  Get it with this request:

```
curl -i ${endpoint}/encrypted-jwt-java/private_key
```

The response will show you a PEM-encoded private key.

You can also get the public key.  This is useful if you want to use an external
system to GENERATE the encrypted JWT or JWE, that you will then verify with
`/verify_jwt` or `/verify_jwe`. Retrieve the public key with this request:

```
curl -i ${endpoint}/encrypted-jwt-java/public_key
```
