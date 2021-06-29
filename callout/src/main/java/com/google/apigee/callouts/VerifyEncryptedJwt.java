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

package com.google.apigee.callouts;

import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.TimeResolver;
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
  private static final long defaultTimeAllowance = 0L;
  private static final long maxTimeAllowance = 60L;
  private static final long minTimeAllowance = 0L;
  private static final long defaultMaxLifetime = -1L;

  public VerifyEncryptedJwt(Map properties) {
    super(properties);
  }

  String getVarPrefix() {
    return "ejwt_";
  };

  private long getTimeAllowance(MessageContext msgCtxt) throws Exception {
    String timeAllowance = (String) this.properties.get("time-allowance");
    if (timeAllowance == null) {
      return defaultTimeAllowance;
    }
    timeAllowance = timeAllowance.trim();
    if (timeAllowance.equals("")) {
      return defaultTimeAllowance;
    }
    timeAllowance = resolveVariableReferences(timeAllowance, msgCtxt);
    if (timeAllowance == null || timeAllowance.equals("")) {
      return defaultTimeAllowance;
    }
    long resolvedTimeAllowance = Long.parseLong(timeAllowance, 10);
    return Math.max(Math.min(resolvedTimeAllowance, maxTimeAllowance), minTimeAllowance);
  }

  private long getMaxAllowableLifetime(MessageContext msgCtxt) throws Exception {
    String maxLifetime = (String) this.properties.get("max-lifetime");
    if (maxLifetime == null) {
      return defaultMaxLifetime;
    }
    maxLifetime = maxLifetime.trim();
    if (maxLifetime.equals("")) {
      return defaultMaxLifetime;
    }
    maxLifetime = resolveVariableReferences(maxLifetime, msgCtxt);
    if (maxLifetime == null || maxLifetime.equals("")) {
      return defaultMaxLifetime;
    }

    Long maxLifetimeInMilliseconds = TimeResolver.resolveExpression(maxLifetime);
    if (maxLifetimeInMilliseconds < 0L) return -1L;
    return (maxLifetimeInMilliseconds / 1000L);
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

    long timeAllowance = getTimeAllowance(msgCtxt);
    long maxLifetime = getMaxAllowableLifetime(msgCtxt);

    Date expDate = claims.getExpirationTime();
    Long secondsRemaining = null;
    /*
     * Comments regarding lifetime and expiry.
     *
     * Token lifetime is subtly different than expiry.
     *
     * The expiry is optional in a token, and if present is expressed as an
     * absolute number of seconds since epoch.  The lifetime is a computed
     * property: the difference between the optional expiry and (notbefore or iat or now), in
     * that order of precedence.
     *
     * If the token carries an expiry claim, this policy will
     * enforce it.
     *
     * If the policy configuration directs the callout to enforce a maximum
     * lifetime of the token, this code wll enforce it.
     *
     ***/
    Long lifetime = null;
    Instant now = Instant.now();

    if (expDate != null) {
      Instant expiry = expDate.toInstant();
      msgCtxt.setVariable(varName("expires"), DateTimeFormatter.ISO_INSTANT.format(expiry));
      msgCtxt.setVariable(varName("expires_seconds"), Long.toString(expiry.getEpochSecond()));
      secondsRemaining = now.until(expiry, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("seconds_remaining"), Long.toString(secondsRemaining));
      if (secondsRemaining + timeAllowance <= 0L)
        throw new IllegalStateException("JWT is expired.");
    }

    Date iatDate = claims.getIssueTime();
    if (iatDate != null) {
      Instant issuedAt = iatDate.toInstant();
      msgCtxt.setVariable(varName("issued_at"), DateTimeFormatter.ISO_INSTANT.format(issuedAt));
    }

    Date nbfDate = claims.getNotBeforeTime();
    if (nbfDate != null) {
      Instant notBefore = nbfDate.toInstant();
      msgCtxt.setVariable(varName("notbefore"), DateTimeFormatter.ISO_INSTANT.format(notBefore));
      msgCtxt.setVariable(varName("notbefore_seconds"), Long.toString(notBefore.getEpochSecond()));
      long age = notBefore.until(now, ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("age"), Long.toString(age));
      if (age + timeAllowance <= 0L) throw new IllegalStateException("JWT is not yet valid.");
    }

    if (expDate != null) {
      Instant anchor =
          (nbfDate != null) ? nbfDate.toInstant() : (iatDate != null) ? iatDate.toInstant() : now;
      lifetime = anchor.until(expDate.toInstant(), ChronoUnit.SECONDS);
      msgCtxt.setVariable(varName("lifetime"), Long.toString(lifetime));
    }

    if (maxLifetime > 0L) {
      if (lifetime == null)
        throw new IllegalStateException(
            "the JWT has an unlimited lifetime which exceeds the configured limit.");

      if (lifetime > maxLifetime)
        throw new IllegalStateException(
            "the JWT has a lifetime that exceeds the configured limit.");
    }
  }
}
