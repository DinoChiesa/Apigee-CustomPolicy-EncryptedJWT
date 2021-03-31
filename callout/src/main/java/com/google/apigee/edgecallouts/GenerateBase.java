// GenerateBase.java
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

package com.google.apigee.edgecallouts;


import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.KeyUtil;
import com.google.apigee.util.TimeResolver;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@IOIntensive
public abstract class GenerateBase extends EncryptedJoseBase implements Execution {
  private static LoadingCache<String, JWKSet> jwksCache;
  private final static int MAX_CACHE_ENTRIES = 128;

  public GenerateBase(Map properties) {
    super(properties);

    jwksCache = Caffeine.newBuilder()
      //.concurrencyLevel(4)
      .maximumSize(MAX_CACHE_ENTRIES)
      .expireAfterAccess(60, TimeUnit.MINUTES)
      .build(new CacheLoader<String, JWKSet>() {
          public JWKSet load(String uri)
            throws MalformedURLException, IOException, ParseException {
            // NB: this will throw an IOException on HTTP error.
            JWKSet jwks = JWKSet.load(new URL(uri));
            return jwks;
          }
        });
  }

  private PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
    String publicKeyString = _getOptionalString(msgCtxt, "public-key");
    if (publicKeyString!= null)
      return KeyUtil.decodePublicKey(publicKeyString);
    String jwksUri = _getOptionalString(msgCtxt, "jwks-uri");
    if (jwksUri == null)
      throw new IllegalStateException("specify one of public-key or jwks-uri.");

    String keyId = _getRequiredString(msgCtxt, "key-id");
    JWKSet jwks = jwksCache.get(jwksUri);
    List<JWK> selected =
      new JWKSelector(new JWKMatcher.Builder()
                      .keyType(KeyType.RSA)
                      .keyID(keyId)
                      .build())
      .select(jwks);

    if (selected.size() == 1) {
      return ((RSAKey)selected.get(0)).toPublicKey();
    }
    throw new IllegalStateException(String.format("key '%s' cannot be found.", keyId));
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

  abstract void encrypt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception;

  static class PolicyConfig {
    public boolean debug;
    public boolean generateId;
    public boolean compress; /* only for generate */
    public String keyEncryptionAlgorithm;
    public String contentEncryptionAlgorithm;
    public PublicKey publicKey;
    public String payload;
    public String header;
    public String keyId;
    public String crit;
    public String outputVar;
    public int lifetime;
    public int notBefore;
  }

  PolicyConfig getPolicyConfig(MessageContext msgCtxt) throws Exception {
    PolicyConfig config = new PolicyConfig();
    config.keyEncryptionAlgorithm = getKeyEncryption(msgCtxt);
    config.contentEncryptionAlgorithm = getContentEncryption(msgCtxt);
    config.publicKey = getPublicKey(msgCtxt);
    config.payload = _getOptionalString(msgCtxt, "payload");
    config.header = _getOptionalString(msgCtxt, "header");
    config.keyId = _getOptionalString(msgCtxt, "key-id");
    config.crit = _getOptionalString(msgCtxt, "crit");
    config.outputVar = _getStringProp(msgCtxt, "output", varName("output"));
    config.lifetime = getExpiry(msgCtxt);
    config.notBefore = getNotBefore(msgCtxt);
    config.generateId = _getBooleanProperty(msgCtxt, "generate-id", false);
    config.compress = _getBooleanProperty(msgCtxt, "compress", false);
    return config;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = true;
    try {
      debug = _getBooleanProperty(msgCtxt, "debug", false);
      clearVariables(msgCtxt);
      PolicyConfig policyConfig = getPolicyConfig(msgCtxt);
      policyConfig.debug = debug;
      encrypt(policyConfig, msgCtxt);
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
