// GenerateEncryptedJwt.java
//
// Copyright (c) 2018-2020 Google LLC.
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

package com.google.apigee.callouts;

import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;

@IOIntensive
public class GenerateEncryptedJwt extends GenerateBase implements Execution {
  public GenerateEncryptedJwt(Map properties) {
    super(properties);
  }

  String getVarPrefix() {
    return "ejwt_";
  };

  void encrypt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception {
    if (policyConfig.keyEncryptionAlgorithm == null)
      throw new IllegalStateException("missing key-encryption.");
    JWEAlgorithm alg = JWEAlgorithm.parse(policyConfig.keyEncryptionAlgorithm);
    if (alg == null) throw new IllegalStateException("invalid key-encryption.");
    if (policyConfig.contentEncryptionAlgorithm == null)
      throw new IllegalStateException("missing content-encryption.");
    EncryptionMethod enc = EncryptionMethod.parse(policyConfig.contentEncryptionAlgorithm);
    if (enc == null) throw new IllegalStateException("invalid content-encryption.");

    msgCtxt.setVariable(varName("alg"), alg.toString());
    msgCtxt.setVariable(varName("enc"), enc.toString());

    JWEHeader.Builder headerBuilder = new JWEHeader.Builder(alg, enc);
    headerBuilder.type(JOSEObjectType.JWT);
    if (policyConfig.crit != null) {
      headerBuilder.criticalParams(new HashSet<String>(Arrays.asList(policyConfig.crit.split("[\\s,]+"))));
    }
    if (policyConfig.header != null) {
      JSONObjectUtils.parse(policyConfig.header)
          .forEach((key, value) -> headerBuilder.customParam(key, value));
    }
    if (policyConfig.keyId != null) {
      headerBuilder.keyID(policyConfig.keyId);
    }
    if (policyConfig.compress) {
      headerBuilder.compressionAlgorithm(CompressionAlgorithm.DEF);
    }
    JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
    if (policyConfig.payload != null) {
      Map<String, Object> map = JSONObjectUtils.parse(policyConfig.payload);
      map.forEach((key, value) -> claimsBuilder.claim(key, value));
      if (!map.containsKey("jti") && policyConfig.generateId) {
        String id = UUID.randomUUID().toString();
        claimsBuilder.jwtID(id);
        msgCtxt.setVariable(varName("jti"), id);
      }
    }

    Instant now = Instant.now();
    claimsBuilder.issueTime(Date.from(now));

    if (policyConfig.notBefore != 0) {
      Instant nbf = now.plus(policyConfig.notBefore, ChronoUnit.SECONDS);
      claimsBuilder.notBeforeTime(Date.from(nbf)); // possibly in the past
    }

    if (policyConfig.expiry != 0) {
      Instant exp = now.plus(policyConfig.expiry, ChronoUnit.SECONDS);
      claimsBuilder.expirationTime(Date.from(exp)); // possibly in the past
    }

    JWEHeader header = headerBuilder.build();
    JWTClaimsSet claims = claimsBuilder.build();
    msgCtxt.setVariable(varName("header"), header.toString());
    msgCtxt.setVariable(varName("payload"), claims.toString());

    EncryptedJWT encryptedJWT = new EncryptedJWT(header, claims);
    RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) policyConfig.publicKey);

    encryptedJWT.encrypt(encrypter);
    String serialized = encryptedJWT.serialize();
    msgCtxt.setVariable(policyConfig.outputVar, serialized);
  }
}
