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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.CalloutUtil;
import com.google.apigee.util.KeyUtil;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@IOIntensive
public class VerifyEncryptedJwt extends EncryptedJwtBase implements Execution {
  public VerifyEncryptedJwt(Map properties) {
    super(properties);
  }

  private String getSourceVar() {
    String source = this.properties.get("source");
    if (source == null || source.equals("")) {
      return "message.header.authorization";
    }
    return source;
  }

  private PrivateKey getPrivateKey(MessageContext msgCtxt) throws Exception {
    return KeyUtil.decodePrivateKey(
        _getRequiredString(msgCtxt, "private-key"),
        _getOptionalString(msgCtxt, "private-key-password"));
  }

  private Set<String> getDeferredCriticalHeaders(MessageContext msgCtxt) throws Exception {
    String critHeaders = _getStringProp(msgCtxt, "crit-headers", null);
    if (critHeaders == null)
      return new HashSet<String>(); // empty set

    return new HashSet<String>(Arrays.asList(critHeaders.split("\\s*,\\s*")));
  }

  void setVariables(Map<String, Object> payloadClaims, Map<String, Object> headerClaims, MessageContext msgCtxt) throws Exception {

    for (Map.Entry<String, Object> entry : payloadClaims.entrySet()) {
      String key = entry.getKey();
      Object value = entry.getValue();
      msgCtxt.setVariable(varName("payload_" + key), value.toString());
    }
    for (Map.Entry<String, Object> entry : headerClaims.entrySet()) {
      String key = entry.getKey();
      Object value = entry.getValue();
      msgCtxt.setVariable(varName("header_" + key), value.toString());
    }
  }

  void decryptJwt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception {
    Object v = msgCtxt.getVariable(policyConfig.source);
    if (v == null) throw new IllegalStateException("Cannot find JWT within source.");
    String jweText = (String) v;
    if (jweText.startsWith("Bearer ")) {
      jweText = jweText.substring(7);
    }
    EncryptedJWT encryptedJWT = EncryptedJWT.parse(jweText);
    RSADecrypter decrypter = new RSADecrypter(policyConfig.privateKey, policyConfig.deferredCritHeaders);
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
    if (!header
        .getAlgorithm()
        .toString()
        .equals(policyConfig.keyEncryptionAlgorithm))
      throw new IllegalStateException("JWT uses unacceptable Key Encryption Algorithm.");

    msgCtxt.setVariable(varName("alg"), header
                        .getAlgorithm()
                        .toString());

    msgCtxt.setVariable(varName("enc"), header
                        .getEncryptionMethod()
                        .toString());

    if (policyConfig.contentEncryptionAlgorithm != null
        && !policyConfig.contentEncryptionAlgorithm.equals("")) {
      if (!header
          .getEncryptionMethod()
          .toString()
          .equals(policyConfig.contentEncryptionAlgorithm))
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

      if (secondsRemaining <= 0L)
        throw new IllegalStateException("JWT is expired.");
    }
    Date nbfDate = claims.getNotBeforeTime();
    if (nbfDate != null) {
      Instant notBefore = nbfDate.toInstant();
      msgCtxt.setVariable(varName("notbefore"), DateTimeFormatter.ISO_INSTANT.format(notBefore));
      msgCtxt.setVariable(varName("notbefore_seconds"), Long.toString(notBefore.getEpochSecond()));
      Instant now = Instant.now();
      long age = notBefore.until(now, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("age"), Long.toString(age));
      if (age <= 0L)
        throw new IllegalStateException("JWT is not yet valid.");
    }

    if (nbfDate!= null && expDate !=null) {
      Instant notBefore = nbfDate.toInstant();
      Instant expiry = expDate.toInstant();
      long lifetime = notBefore.until(expiry, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("lifetime"), Long.toString(lifetime));
    }
  }

  static class PolicyConfig {
    public boolean debug;
    public String keyEncryptionAlgorithm;
    public String contentEncryptionAlgorithm;
    public RSAPrivateKey privateKey;
    public Set<String> deferredCritHeaders;
    public String source;
  }

  PolicyConfig getPolicyConfiguration(MessageContext msgCtxt) throws Exception {
    PolicyConfig config = new PolicyConfig();
    config.keyEncryptionAlgorithm = getKeyEncryption(msgCtxt);
    config.contentEncryptionAlgorithm = getContentEncryption(msgCtxt);
    config.privateKey = (RSAPrivateKey) getPrivateKey(msgCtxt);
    config.deferredCritHeaders = getDeferredCriticalHeaders(msgCtxt);
    config.source = getSourceVar();
    return config;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = true;
    try {
      debug = _getBooleanProperty(msgCtxt, "debug", false);
      clearVariables(msgCtxt);
      PolicyConfig policyConfig = getPolicyConfiguration(msgCtxt);
      policyConfig.debug = debug;
      decryptJwt(policyConfig, msgCtxt);
    } catch (Exception e) {
      if (debug) {
        //e.printStackTrace();
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
