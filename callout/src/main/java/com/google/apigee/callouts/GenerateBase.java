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
import com.nimbusds.jose.jwk.KeyUse;
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
import java.util.stream.Collectors;

@IOIntensive
public abstract class GenerateBase extends EncryptedJoseBase implements Execution {
  private static LoadingCache<String, JWKSet> jwksRemoteCache;
  private static LoadingCache<String, JWKSet> jwksLocalCache;
  private static final int MAX_CACHE_ENTRIES = 128;
  private static final int CACHE_EXPIRY_IN_MINUTES = 5;

  static {
    jwksRemoteCache =
        Caffeine.newBuilder()
            // .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(CACHE_EXPIRY_IN_MINUTES, TimeUnit.MINUTES)
            .build(
                new CacheLoader<String, JWKSet>() {
                  public JWKSet load(String uri)
                      throws MalformedURLException, IOException, ParseException {
                    // NB: this will throw an IOException on HTTP error.
                    return JWKSet.load(new URL(uri));
                  }
                });

    jwksLocalCache =
        Caffeine.newBuilder()
            // .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(CACHE_EXPIRY_IN_MINUTES, TimeUnit.MINUTES)
            .build(
                new CacheLoader<String, JWKSet>() {
                  public JWKSet load(String jwksJson) throws ParseException {
                    // NB: this can throw an Exception on parse error.
                   return JWKSet.parse(jwksJson);
                  }
                });
  }

  public GenerateBase(Map properties) {
    super(properties);
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
    /*
     * Do not match on .keyUse(KeyUse.ENCRYPTION)
     *
     * It's possible that some keys miss the "use" flag.
     * So we will filter later.
     **/
  }

  private PublicKey selectKey(List<JWK> list, Consumer<String> onKeySelected) throws Exception {
    JWK randomItem = list.get(new java.util.Random().nextInt(list.size()));
    onKeySelected.accept(randomItem.getKeyID());
    return ((RSAKey) randomItem).toPublicKey();
  }

  private PublicKey getPublicKeyFromJwks(MessageContext msgCtxt, Consumer<String> onKeySelected)
      throws Exception {
    JWKSet jwks = null;
    String jwksJson = _getOptionalString(msgCtxt, "jwks");
    if (jwksJson != null) {
      jwks = jwksLocalCache.get(jwksJson);
    } else {
      String jwksUri = _getOptionalString(msgCtxt, "jwks-uri");
      if (jwksUri == null)
        throw new IllegalStateException("specify one of {public-key, jwks, jwks-uri}.");
      jwks = jwksRemoteCache.get(jwksUri);
    }

    String keyId = _getOptionalString(msgCtxt, "key-id");
    if (keyId != null) {
      // find key with specific kid. Ignore use.
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

    List<JWK> filtered = new JWKSelector(matcherBuilder().build()).select(jwks)
      .stream()
      .filter(k -> k.getKeyUse() == null || k.getKeyUse().equals(KeyUse.ENCRYPTION))
      .collect(Collectors.toList());

    if (filtered.size() == 0) {
      throw new IllegalStateException("could not find any appropriate RSA keys.");
    }
    return selectKey(filtered, onKeySelected);
  }

  private String getOutputVar(MessageContext msgCtxt) throws Exception {
    return _getStringProp(msgCtxt, "output", varName("output"));
  }

  private int getTimeIntervalString(MessageContext msgCtxt, String propertyName) throws Exception {
    String timeDurationString = _getOptionalString(msgCtxt, propertyName);
    if (timeDurationString == null) return 0;
    timeDurationString = timeDurationString.trim();
    Long durationInMilliseconds = TimeResolver.resolveExpression(timeDurationString);
    return ((Long) (durationInMilliseconds / 1000L)).intValue();
  }

  private int getExpiry(MessageContext msgCtxt) throws Exception {
    return getTimeIntervalString(msgCtxt, "expiry");
  }

  private int getNotBefore(MessageContext msgCtxt) throws Exception {
    return getTimeIntervalString(msgCtxt, "not-before");
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
    public int expiry;
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
    if (config.keyId == null) config.keyId = _getOptionalString(msgCtxt, "key-id");
    config.payload = _getOptionalString(msgCtxt, "payload");
    config.header = _getOptionalString(msgCtxt, "header");
    config.crit = _getOptionalString(msgCtxt, "crit");
    config.outputVar = _getStringProp(msgCtxt, "output", varName("output"));
    config.expiry = getExpiry(msgCtxt);
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
        msgCtxt.setVariable(varName("stacktrace"), getStackTraceAsString(e));
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}
