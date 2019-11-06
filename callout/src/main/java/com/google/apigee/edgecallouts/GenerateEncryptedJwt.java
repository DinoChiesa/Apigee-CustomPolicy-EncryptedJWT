// GenerateEncryptedJwt.java
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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.KeyUtil;
import com.google.apigee.util.TimeResolver;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@IOIntensive
public class GenerateEncryptedJwt extends EncryptedJwtBase implements Execution {
  public GenerateEncryptedJwt(Map properties) {
    super(properties);
  }

  private PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    return KeyUtil.decodePublicKey(_getRequiredString(msgCtxt, "public-key"));
  }

  private String getOutputVar(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "output", varName("output"));
  }

  private int getExpiry(MessageContext msgCtxt) throws Exception {
    String lifetimeString = _getOptionalString(msgCtxt, "expiry");
    if (lifetimeString == null) return -1;
    lifetimeString = lifetimeString.trim();
    Long durationInMilliseconds = TimeResolver.resolveExpression(lifetimeString);
    if (durationInMilliseconds < 0L) return -1;
    return ((Long) (durationInMilliseconds / 1000L)).intValue();
  }

  private int getNotBefore(MessageContext msgCtxt) throws Exception {
    String notBeforeString = _getOptionalString(msgCtxt, "not-before");
    if (notBeforeString == null) return -1;
    notBeforeString = notBeforeString.trim();
    Long durationInMilliseconds = TimeResolver.resolveExpression(notBeforeString);
    if (durationInMilliseconds < 0L) return -1;
    return ((Long) (durationInMilliseconds / 1000L)).intValue();
  }

  void setVariables(
      Map<String, Object> payloadClaims, Map<String, Object> headerClaims, MessageContext msgCtxt)
      throws Exception {

    for (Map.Entry<String, Object> entry : payloadClaims.entrySet()) {
      String key = entry.getKey();
      Object value = entry.getValue();
      msgCtxt.setVariable(varName("payload_" + key), value.toString());
    }
  }

  void encryptJwt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception {
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
    if (policyConfig.header != null) {
      JSONObjectUtils.parse(policyConfig.header)
        .forEach((key, value) -> headerBuilder.customParam(key, value) );
      // Map<String, Object> map = JSONObjectUtils.parse(policyConfig.header);
      // map.forEach((key, value) -> headerBuilder.customParam(key, value) );
    }

    JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
    if (policyConfig.payload != null) {
      Map<String, Object> map = JSONObjectUtils.parse(policyConfig.payload);
      for (Map.Entry<String, Object> entry : map.entrySet()) {
        String key = entry.getKey();
        Object value = entry.getValue();
        claimsBuilder.claim(key, value);
      }
      if (!map.containsKey("jti") && policyConfig.generateId) {
        String id = UUID.randomUUID().toString();
        claimsBuilder.jwtID(id);
        msgCtxt.setVariable(varName("jti"), id);
      }
    }

    Instant now = Instant.now();
    claimsBuilder.issueTime(Date.from(now));

    if (policyConfig.lifetime > 0) {
      Instant exp = now.plus(policyConfig.lifetime, ChronoUnit.SECONDS);
      claimsBuilder.expirationTime(Date.from(exp));
    }
    if (policyConfig.notBefore > 0) {
      Instant nbf = now.plus(policyConfig.notBefore, ChronoUnit.SECONDS);
      claimsBuilder.notBeforeTime(Date.from(nbf));
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

  static class PolicyConfig {
    public boolean debug;
    public boolean generateId;
    public String keyEncryptionAlgorithm;
    public String contentEncryptionAlgorithm;
    public PublicKey publicKey;
    public String payload;
    public String header;
    public String outputVar;
    public int lifetime;
    public int notBefore;
  }

  PolicyConfig getPolicyConfiguration(MessageContext msgCtxt) throws Exception {
    PolicyConfig config = new PolicyConfig();
    config.keyEncryptionAlgorithm = getKeyEncryption(msgCtxt);
    config.contentEncryptionAlgorithm = getContentEncryption(msgCtxt);
    config.publicKey = getPublicKey(msgCtxt);
    config.payload = _getOptionalString(msgCtxt, "payload");
    config.header = _getOptionalString(msgCtxt, "header");
    config.outputVar = _getStringProp(msgCtxt, "output", varName("output"));
    config.lifetime = getExpiry(msgCtxt);
    config.notBefore = getNotBefore(msgCtxt);
    config.generateId = _getBooleanProperty(msgCtxt, "generate-id", false);
    return config;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = true;
    try {
      debug = _getBooleanProperty(msgCtxt, "debug", false);
      clearVariables(msgCtxt);
      PolicyConfig policyConfig = getPolicyConfiguration(msgCtxt);
      policyConfig.debug = debug;
      encryptJwt(policyConfig, msgCtxt);
    } catch (Exception e) {
      if (debug) {
        // e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
