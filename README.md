# Encrypted JWT callout

This directory contains the Java source code for
Java callouts for Apigee Edge that performs Generates or Verifies encrypted JWT.

## License

This code is Copyright (c) 2017-2019 Google LLC, and is released under the Apache Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Disclaimer

This example is not an official Google product, nor is it part of an official Google product.

## Using the Custom Policy

You do not need to build the Jar in order to use the custom policy.

When you use the policy to generate an encrypted JWT, the resulting JWT can be
decrypted by other systems with the matching private key. Likewise, when you use
the policy to verify an encrypted JWT, the policy will work with any compliant
encrypted JWT that uses alg = RSA-OAEP-256.

## Policy Configuration

There is a variety of options. Some examples follow.

## Example: Generation of an Encrypted JWT

  ```xml
  <JavaCallout name="Java-JWTGeneration">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP-256</Property>
      <Property name='content-encryption'>A256GCM</Property>
      <Property name='payload'>{ "sub":"dino", "unk":"600c3efa-e48e-49c8-b6d9-e6bb9b94ad52"}</Property>
      <Property name='expires'>1h</Property>
      <Property name='public-key'>{my_public_key}</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.GenerateEncryptedJwt</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191104.jar</ResourceURL>
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
| payload            | required. name of a variable containing a JSON string that includes properties for the payload of the JWT.          |
| key-encryption     | required. name of the key encryption algorithm. Must be RSA-OAEP-256.                                               |
| content-encryption | required. name of the content encryption algorithm. One of A256GCM, A128GCM, A265GCM, or one of the CBC algorithms. |
| expires            | optional. an interval, like 5m, 1h, 1d, expressing the desired time of expiry of the JWT, measured from now.        |
| not-before         | optional. an interval as above, expressing the not-before time of the JWT, measured from now.                       |
| output             | optional. name of the variable in which to store the output. Defaults to ejwt_output.                               |


### Example: Basic Verification of an Encrypted JWT

  ```xml
  <JavaCallout name="Java-JWTVerification1">
    <Properties>
      <Property name='key-encryption'>RSA-OAEP-256</Property>
      <Property name='private-key'>{private.my_private_key}</Property>
    </Properties>
    <ClassName>com.google.apigee.edgecallouts.VerifyEncryptedJwt</ClassName>
    <ResourceURL>java://edge-callout-encrypted-jwt-20191104.jar</ResourceURL>
  </JavaCallout>
  ```

* the class is VerifyEncryptedJwt, so the policy will Verify an encrypted JWT
* The policy will deserialize the private key  from the PEM string contained in
  the variable `private.my_private_key`
* The policy will verify the effective times on the JWT (exp and nbf)
* There is no 'source' property defined so the JWT is retrieved from the
  Authorization header


### Properties for Verification

These are the properties available on the policy:

| Property             | Description                                                                                                                               |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| private-key          | required when action = "decrypt". a PEM string representing the private key.                                                              |
| private-key-password | optional. a password to use with an encrypted private key.                                                                                |
| key-encryption       | required. name of the key encryption algorithm. Must be RSA-OAEP-256.                                                                     |
| content-encryption   | optional. name of the content encryption algorithm. One of A256GCM, A128GCM, A265GCM, or one of the CBC algorithms.                       |
| source               | optional. name of the context variable containing the data to encrypt or decrypt. Do not surround in curly braces. Defaults to `.message.header.authorization`. |
| crit-headers         | optional. comma-separated list of header names that are critical; to be handled by the proxy later.  |



## Detecting Success and Errors

The policy will return ABORT and set the context variable `crypto_error` if there has been any error at runtime. Your proxy bundles can check this variable in `FaultRules`.

Errors can result at runtime if:

* you specify an invalid configuration
* You use VerifyEncryptedJwt and the inbound JWT is expired
* You use VerifyEncryptedJwt and the inbound JWT uses an alg or enc that is not
  consistent with the policy configuration.

## Building the Jar

You do not need to build the Jar in order to use the custom policy. The custom policy is
ready to use, with policy configuration. You need to re-build the jar only if you want
to modify the behavior of the custom policy. Before you do that, be sure you understand
all the configuration options - the policy may be usable for you without modification.

If you do wish to build the jar, you can use [maven](https://maven.apache.org/download.cgi) to do so. The build requires JDK8. Before you run the build the first time, you need to download the Apigee Edge dependencies into your local maven repo.

Preparation, first time only: `./buildsetup.sh`

To build: `mvn clean package`

The Jar source code includes tests.

If you edit policies offline, copy [the jar file for the custom policy](callout/target/edge-callout-encrypted-jwt-20191104.jar)  to your apiproxy/resources/java directory.  If you don't edit proxy bundles offline, upload that jar file into the API Proxy via the Edge API Proxy Editor .


## Build Dependencies

* Apigee Edge expressions v1.0
* Apigee Edge message-flow v1.0
* Bouncy Castle 1.62
* NimbusDS jose-jwt v8.2

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

