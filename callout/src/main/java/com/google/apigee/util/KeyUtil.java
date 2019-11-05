// Copyright 2018-2019 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package com.google.apigee.util;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

public class KeyUtil {

  private KeyUtil () {} // uncomment if wanted

  private static String reformIndents(String s) {
    return s.trim().replaceAll("([\\r|\\n] +)","\n");
  }

  public static PublicKey decodePublicKey(String publicKeyString) throws IOException, PEMException {
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    publicKeyString = reformIndents(publicKeyString);
    PEMParser pemParser = new PEMParser(new StringReader(publicKeyString));
    Object object = pemParser.readObject();
    if (object == null) {
      throw new IllegalStateException("unable to read anything when decoding public key");
    }
    try {
      return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
    }
    catch (ClassCastException exc1) {
      throw new IllegalStateException("that does not appear to be a public key.", exc1);
    }
  }

  public static RSAPrivateKey decodePrivateKey(String privateKeyPemString, String password) throws IOException, PKCSException, PEMException, OperatorCreationException {
    if (privateKeyPemString == null) {
      throw new IllegalStateException("PEM String is null");
    }
    if (password == null) password = "";
    privateKeyPemString = reformIndents(privateKeyPemString);
    PEMParser pr = null;
    try {
      pr = new PEMParser(new StringReader(privateKeyPemString));
      Object o = pr.readObject();

      if (o == null) {
        throw new IllegalStateException("Parsed object is null. Bad input.");
      }
      if (!((o instanceof PEMEncryptedKeyPair)
            || (o instanceof PKCS8EncryptedPrivateKeyInfo)
            || (o instanceof PrivateKeyInfo)
            || (o instanceof PEMKeyPair))) {
        // System.out.printf("found %s\n", o.getClass().getName());
        throw new IllegalStateException("Didn't find OpenSSL key. Found: " + o.getClass().getName());
      }

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (o instanceof PEMKeyPair) {
        // eg, "openssl genrsa -out keypair-rsa-2048-unencrypted.pem 2048"
        return (RSAPrivateKey) converter.getPrivateKey(((PEMKeyPair) o).getPrivateKeyInfo());
      }

      if (o instanceof PrivateKeyInfo) {
        // eg, "openssl genpkey  -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out keypair.pem"
        return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
      }

      if (o instanceof PKCS8EncryptedPrivateKeyInfo) {
        // eg, "openssl genpkey -algorithm rsa -aes-128-cbc -pkeyopt rsa_keygen_bits:2048 -out private-encrypted.pem"
        PKCS8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) o;
        JceOpenSSLPKCS8DecryptorProviderBuilder decryptorProviderBuilder =
          new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decryptorProvider =
          decryptorProviderBuilder.build(password.toCharArray());
        PrivateKeyInfo privateKeyInfo =
          pkcs8EncryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
      }

      if (o instanceof PEMEncryptedKeyPair) {
        // eg, "openssl genrsa -aes256 -out private-encrypted-aes-256-cbc.pem 2048"
        PEMDecryptorProvider decProv =
          new JcePEMDecryptorProviderBuilder().setProvider("BC").build(password.toCharArray());
        KeyPair keyPair = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
        return (RSAPrivateKey) keyPair.getPrivate();
      }
    }
    finally {
      if (pr != null) {
        pr.close();
      }
    }
    throw new IllegalStateException("unknown PEM object");
  }

}
