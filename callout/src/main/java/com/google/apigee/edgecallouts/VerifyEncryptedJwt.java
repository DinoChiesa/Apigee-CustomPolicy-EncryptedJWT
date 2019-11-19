// VerifyEncryptedJwt.java
//
// This is the callout class for the VerifyEncryptedJwt custom policy for Apigee Edge.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2018-2019 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// @author: Dino Chiesa
//

package com.google.apigee.edgecallouts;

import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;

@IOIntensive
public class VerifyEncryptedJwt extends VerifyBase implements Execution {
  public VerifyEncryptedJwt(Map properties) {
    super(properties);
  }

  void decrypt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception {
    Object v = msgCtxt.getVariable(policyConfig.source);
    if (v == null) throw new IllegalStateException("Cannot find JWT within source.");
    String jweText = (String) v;
    if (jweText.startsWith("Bearer ")) {
      jweText = jweText.substring(7);
    }
    EncryptedJWT encryptedJWT = EncryptedJWT.parse(jweText);
    RSADecrypter decrypter =
        new RSADecrypter(policyConfig.privateKey, policyConfig.deferredCritHeaders);
    encryptedJWT.decrypt(decrypter);
    if (encryptedJWT.getPayload() != null) {
      String payload = encryptedJWT.getPayload().toString();
      msgCtxt.setVariable(varName("payload"), payload);
    }
    if (encryptedJWT.getHeader() == null)
      throw new IllegalStateException("JWT included no header.");

    JWEHeader header = encryptedJWT.getHeader();
    msgCtxt.setVariable(varName("header"), header.toString());

    JWTClaimsSet claims = encryptedJWT.getJWTClaimsSet();
    setVariables(claims.getClaims(), header.toJSONObject(), msgCtxt);

    // verify configured Key Encryption Alg and maybe Content Encryption Alg
    if (!header.getAlgorithm().toString().equals(policyConfig.keyEncryptionAlgorithm))
      throw new IllegalStateException("JWT uses unacceptable Key Encryption Algorithm.");

    msgCtxt.setVariable(varName("alg"), header.getAlgorithm().toString());

    msgCtxt.setVariable(varName("enc"), header.getEncryptionMethod().toString());

    if (policyConfig.contentEncryptionAlgorithm != null
        && !policyConfig.contentEncryptionAlgorithm.equals("")) {
      if (!header.getEncryptionMethod().toString().equals(policyConfig.contentEncryptionAlgorithm))
        throw new IllegalStateException("JWT uses unacceptable Content Encryption Algorithm.");
    }

    Date expDate = claims.getExpirationTime();
    if (expDate != null) {
      Instant expiry = expDate.toInstant();
      msgCtxt.setVariable(varName("expires"), DateTimeFormatter.ISO_INSTANT.format(expiry));
      msgCtxt.setVariable(varName("expires_seconds"), Long.toString(expiry.getEpochSecond()));
      Instant now = Instant.now();
      long secondsRemaining = now.until(expiry, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("seconds_remaining"), Long.toString(secondsRemaining));

      if (secondsRemaining <= 0L) throw new IllegalStateException("JWT is expired.");
    }
    Date nbfDate = claims.getNotBeforeTime();
    if (nbfDate != null) {
      Instant notBefore = nbfDate.toInstant();
      msgCtxt.setVariable(varName("notbefore"), DateTimeFormatter.ISO_INSTANT.format(notBefore));
      msgCtxt.setVariable(varName("notbefore_seconds"), Long.toString(notBefore.getEpochSecond()));
      Instant now = Instant.now();
      long age = notBefore.until(now, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("age"), Long.toString(age));
      if (age <= 0L) throw new IllegalStateException("JWT is not yet valid.");
    }

    if (nbfDate != null && expDate != null) {
      Instant notBefore = nbfDate.toInstant();
      Instant expiry = expDate.toInstant();
      long lifetime = notBefore.until(expiry, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("lifetime"), Long.toString(lifetime));
    }
  }
}
