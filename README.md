# Encrypted JWT callout

This directory contains the Java source code for Java callouts for Apigee that
Generates or Verifies encrypted JWT that use RSA encryption (RSA-OAEP
or RSA-OAEP-256).  Also callouts that generate or verify JWE (JWE with non-JSON
encrypted payloads) with RSA algorithms.

* Please note: Back in 2017, Google [announced a practical method of producing a
  "collision" for
  SHA-1](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html).
  And in that announcement, stressed that it is time to retire the SHA-1 hash.
  RSA-OAEP depends on the SHA-1 hash.  For that reason, I discourage the use of
  RSA-OAEP in lieu of RSA-OAEP-256, which relies on the more secure SHA-256
  hash. Security is complicated, and depends on a layering of protocols, hashes,
  and algorithms. Take care when implementing RSA-OAEP.


RSA-OAEP is discouraged deprecated by

## License

This code is Copyright (c) 2017-2019 Google LLC, and is released under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policy.

There are four different classes:

| class                                               | purpose                                |
|-----------------------------------------------------|----------------------------------------|
| com.google.apigee.edgecallouts.GenerateEncryptedJwt | generate an encrypted JWT.             |
| com.google.apigee.edgecallouts.VerifyEncryptedJwt   | verify an encrypted JWT.               |
| com.google.apigee.edgecallouts.GenerateJwe          | generate a JWE with arbitrary payload. |
| com.google.apigee.edgecallouts.VerifyJwe            | verify a JWE with arbitrary payload.   |

When you use the policy to generate an encrypted JWT, the resulting JWT can be
decrypted by other systems that have access to the matching private key. Likewise, when you use
the policy to verify an encrypted JWT, the policy will work with any compliant
encrypted JWT that uses alg = RSA-OAEP-256 or alg = RSA-OAEP.

Likewise with the JWE variants.

## Policy Configuration

There is a variety of options. Some examples follow.

## Example: Generation of an Encrypted JWT

  ```xml
  <JavaCallout name="Java-JWTGeneration">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP-256</Property>
      <Property name='content-encryption'>A256GCM</Property>
      <Property name='payload'>{ "sub":"dino", "unk":"600c3efa-e48e-49c8-b6d9-e6bb9b94ad52"}</Property>
      <Property name='expiry'>1h</Property>
      <Property name='public-key'>{my_public_key}</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.GenerateEncryptedJwt</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191204.jar</ResourceURL>
  </JavaCallout>
  ```

Here's what will happen with this policy configuration:

* the class is GenerateEncryptedJwt, so the policy will Generate an encrypted JWT
* The public key will be deserialized from the PEM string in the variable `my_public_key`
* The JWT will expire 1 hour after generation
* There is no 'output' property defined so the JWT is stored into context variable 'ejwt_output'

To decrypt the resulting ciphertext, either within Apigee with this policy, or
using some other system, the decryptor needs to use the corresponding private
key.


### Properties for Generation

These are the properties available on the policy:

| Property           | Description                                                                                                         |
|--------------------|---------------------------------------------------------------------------------------------------------------------|
| public-key         | required. a PEM string representing the public key.                                                                 |
| key-encryption     | required. name of the key encryption algorithm. Must be RSA-OAEP-256 or RSA-OAEP.                                   |
| content-encryption | required. name of the content encryption algorithm. One of A256GCM, A128GCM, A265GCM, or one of the CBC algorithms. |
| payload            | optional. a JSON string that includes additional properties for the payload of the JWT.                             |
| header             | optional. a JSON string that includes additional properties for the header of the JWT.                              |
| expiry             | optional. an interval, like 5m, 1h, 1d, expressing the desired time of expiry of the JWT, measured from now.        |
| not-before         | optional. an interval as above, expressing the not-before time of the JWT, measured from now.                       |
| generate-id        | optional. boolean, true or false. Defaults to false. Whether to generate a jti claim.                               |
| compress           | optional. boolean, true or false. Defaults to false. Whether to compress the payload before encrypting.             |
| output             | optional. name of the variable in which to store the output. Defaults to `ejwt_output`.                             |


### Example: Basic Verification of an Encrypted JWT

  ```xml
  <JavaCallout name="Java-JWTVerification1">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP-256</Property>
      <Property name='private-key'>{private.my_private_key}</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.VerifyEncryptedJwt</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191204.jar</ResourceURL>
  </JavaCallout>
  ```

* the class is VerifyEncryptedJwt, so the policy will Verify an encrypted JWT
* There is no 'source' property defined so the JWT is retrieved from the
  Authorization header
* the key encryption is specified as RSA-OAEP-256, so the policy will verify
  that the inbound JWT uses that encryption, and will reject a JWT with any other alg.
* The policy will deserialize the private key from the PEM string contained in
  the variable `private.my_private_key`, and will decrypt with that key.
* If decryption succeeds, the policy will verify the effective times on the JWT
  (exp and nbf), if they exist.

### Example: Verification of an Encrypted JWT with a specific content encryption

  ```xml
  <JavaCallout name="Java-JWTVerification1">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP-256</Property>
      <Property name='content-encryption'>A256GCM</Property>
      <Property name='private-key'>{private.my_private_key}</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.VerifyEncryptedJwt</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191204.jar</ResourceURL>
  </JavaCallout>
  ```

* all options act as in the previous example
* the one new option `content-encryption`, tells the policy to require that the
  inbound JWT uses the `A256GCM` encryption method. If the inbound JWT uses any
  other encryption, the verification will fail.


### Properties for Verification

These are the properties available on the policy:

| Property             | Description                                                                                                                               |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| private-key          | required when action = "decrypt". a PEM string representing the private key.                                                              |
| private-key-password | optional. a password to use with an encrypted private key.                                                                                |
| key-encryption       | required. name of the key encryption algorithm. Must be RSA-OAEP-256 or RSA-OAEP.                                                         |
| content-encryption   | optional. name of the content encryption algorithm. One of A256GCM, A128GCM, A265GCM, or one of the CBC algorithms.                       |
| source               | optional. name of the context variable containing the data to encrypt or decrypt. Do not surround in curly braces. Defaults to `message.header.authorization`. |
| crit-headers         | optional. comma-separated list of header names that are critical; to be handled by the proxy later.  |


### Verifying JWE

You can verify generic JWE as well. While encrypted JWT are JWE with JSON
payloads, generic JWE are JWE with arbitrary bytestream payloads (typically they
are not JSON). The options for the callout are the same. The callout `ClassName`
is different:

  ```xml
  <JavaCallout name="Java-JWEVerification1">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP</Property>
      <Property name='content-encryption'>A256GCM</Property>
      <Property name='private-key'>{private.my_private_key}</Property>
    </Properties>
    <!-- Verify a JWE containing a non-JSON payloads -->
    <ClassName>com.google.apigee.edgecallouts.VerifyJwe</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191204.jar</ResourceURL>
  </JavaCallout>
  ```

### Generating JWE

You can generate generic JWE, too. The options for the callout are the
same. The callout `ClassName` is different:

  ```xml
  <JavaCallout name="Java-JWEGenerate">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP</Property>
      <Property name='content-encryption'>A256GCM</Property>
      <Property name='payload'>anything-you-like-here</Property>
      <Property name='public-key'>{my_public_key}</Property>
    </Properties>
    <!-- Generate a JWE for non-JSON payloads -->
    <ClassName>com.google.apigee.edgecallouts.GenerateJwe</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191204.jar</ResourceURL>
  </JavaCallout>
  ```


## About PEM-encoded Keys

Private keys should look like this:
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXk9k01JrhGQf1
8xaz45QmARgwI/g25gO8hP9iBABk3iNBY96+Kr65ReY8Ivof6Y2yha0ZPEwEfehQ
...
hHYu+QiRZnABbpD9C1+Akh4dG97Woyfd5igBsT1Ovs9PDCN0rO4I2nJHrNLJSPte
OtpRWoF2/LERvp6RNeXthgs=
-----END PRIVATE KEY-----
```



Public keys should look like this:
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA15PZNNSa4RkH9eAeJ8ph
57WhvUmANpBEDqP0SuHzNl3HmxbEiUPBoBNQAtRpVlOWM0t+FltMORjGXtntjSBs
...
I3DFmXb0ny3uCUCfCRtHnpAU0gfjWBiwkZ/R2OhZOW877GGcNMKVTnFT6911gGMi
SwIDAQAB
-----END PUBLIC KEY-----
```


## About crit-headers

The JWT specification includes an option to specify ["critical
headers"](https://tools.ietf.org/html/rfc7515#section-4.1.11) in the
`crit` field of the header of the JWT. (See also the [JWE
spec](https://tools.ietf.org/html/rfc7516#section-4.1.13)) . The value of the
`crit` field is a list of header names. Via this notation, the JWT asserts that
there are headers contained in the JWT which are critical and which MUST be
understood by any consumer or reader. The reader MUST reject any JWT containing
headers on the `crit` list that it does not understand.

To communicate headers that are understood, configure the policy with the
`crit-headers` property. When the VerifyEncryptedJwt callout process an inbound
JWT that contains crit headers, the verification will succeed if and only if
those headers are in the `crit-headers` list in the policy configuration,

If your inbound JWT do not include a `crit` header

## Detecting Success and Errors

The policy will return ABORT and set the context variable `ejwt_error` if there has been any error at runtime. Your proxy bundles can check this variable in `FaultRules`.

Errors can result at runtime if:

* You specify an invalid configuration, for example an unsupported value for
  key-encryption or content-encryption
* You use VerifyEncryptedJwt and the inbound JWT is expired
* You use VerifyEncryptedJwt and the inbound JWT uses an `alg` or `enc` that is not
  consistent with the policy configuration.

## Example Bundle

There is an [example bundle](./bundle) that demonstrates the use of the API
Proxy.

Example request to generate an encrypted JWT:

```
ORG=myorg
ENV=myenv
curl -i -X POST https://$ORG-$ENV.apigee.net/encrypted-jwt/generate_jwt -d ''
```

The result will be a JWT. You can paste it into a JWT decoder like [this
one](https://dinochiesa.github.io/jwt/) to examine the header. But since it's an
encrypted JWT you will not be able to see the payload unless you decrypt it.

To verify and decrypt that JWT, first set a shell variable to the returned
value:
```
JWT=eyJ0eXAiOiJKV1QiLCJlbmMi...
```

Then verify it:

```
curl -i -X POST https://$ORG-$ENV.apigee.net/encrypted-jwt/verify_jwt  \
  -d "JWT=$JWT"
```


## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use
[maven](https://maven.apache.org/download.cgi) to do so. The build requires
JDK8. Before you run the build the first time, you need to download the Apigee
Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy [the jar file for the custom policy](callout/target/edge-callout-encrypted-jwt-20191204.jar)  to your apiproxy/resources/java directory.  If you don't edit proxy bundles offline, upload that jar file into the API Proxy via the Edge API Proxy Editor .


## Build Dependencies

* Apigee Edge expressions v1.0
* Apigee Edge message-flow v1.0
* Bouncy Castle 1.64
* NimbusDS jose-jwt v8.2.1

These jars are specified in the pom.xml file.

Aside from the first two, you will need to upload these Jars as resources to your Apigee instance, either
with the API Proxy or with the organization or environment.

## Author

Dino Chiesa
godino@google.com

## Bugs

* The policies support only RSA-OAEP-256 for a Key encryption algorithm.
* the GenerateEncryptedJwt does not considers `crit`
  header parameters
* the VerifyEncryptedJwt does not provide a way to explicitly enforce values of `crit`
  header parameters
* there is no "allowable clock skew" parameter for VerifyEncryptedJwt.
