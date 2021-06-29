// GenerateBase.java
//
// Copyright (c) 2018-2021 Google LLC.
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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.apigee.util.KeyUtil;
import com.google.apigee.util.TimeResolver;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@IOIntensive
public abstract class GenerateBase extends EncryptedJoseBase implements Execution {
  private static LoadingCache<String, JWKSet> jwksCache;
  private static final int MAX_CACHE_ENTRIES = 128;

  public GenerateBase(Map properties) {
    super(properties);

    jwksCache =
        Caffeine.newBuilder()
            // .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(60, TimeUnit.MINUTES)
            .build(
                new CacheLoader<String, JWKSet>() {
                  public JWKSet load(String uri)
                      throws MalformedURLException, IOException, ParseException {
                    // NB: this will throw an IOException on HTTP error.
                    JWKSet jwks = JWKSet.load(new URL(uri));
                    return jwks;
                  }
                });
  }

  private PublicKey getPublicKey(MessageContext msgCtxt, Consumer<String> onKeySelected)
      throws Exception {
    String publicKeyString = _getOptionalString(msgCtxt, "public-key");
    return (publicKeyString != null)
        ? KeyUtil.decodePublicKey(publicKeyString)
        : getPublicKeyFromJwks(msgCtxt, onKeySelected);
  }

  private static JWKMatcher.Builder matcherBuilder() {
    return new JWKMatcher.Builder().keyType(KeyType.RSA);
  }

  private PublicKey selectKey(List<JWK> list, Consumer<String> onKeySelected) throws Exception {
    JWK randomItem = list.get(new java.util.Random().nextInt(list.size()));
    onKeySelected.accept(randomItem.getKeyID());
    return ((RSAKey) randomItem).toPublicKey();
  }

  private PublicKey getPublicKeyFromJwks(MessageContext msgCtxt, Consumer<String> onKeySelected)
      throws Exception {
    String jwksUri = _getOptionalString(msgCtxt, "jwks-uri");
    if (jwksUri == null) throw new IllegalStateException("specify one of public-key or jwks-uri.");

    String keyId = _getOptionalString(msgCtxt, "key-id");
    JWKSet jwks = jwksCache.get(jwksUri);
    if (keyId != null) {
      List<JWK> filtered = new JWKSelector(matcherBuilder().keyID(keyId).build()).select(jwks);

      if (filtered.size() == 0) {
        throw new IllegalStateException(String.format("a key with kid '%s' was not found.", keyId));
      }
      if (filtered.size() == 1) {
        return selectKey(filtered, onKeySelected);
      }
      throw new IllegalStateException(
          String.format("more than one key with kid '%s' found.", keyId));
    }
    List<JWK> filtered = new JWKSelector(matcherBuilder().build()).select(jwks);

    if (filtered.size() == 0) {
      throw new IllegalStateException("could not find any RSA keys.");
    }
    return selectKey(filtered, onKeySelected);
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
    config.publicKey =
        getPublicKey(
            msgCtxt,
            kid -> {
              msgCtxt.setVariable(varName("selected_key_id"), kid);
              config.keyId = kid;
            });
    if (config.keyId==null)
      config.keyId = _getOptionalString(msgCtxt, "key-id");
    config.payload = _getOptionalString(msgCtxt, "payload");
    config.header = _getOptionalString(msgCtxt, "header");
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
