// GenerateBase.java
//
// Copyright (c) 2018-2024 Google LLC.
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
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.apigee.util.KeyUtil;
import com.google.apigee.util.TimeResolver;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

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
                    try {
                      return JWKSet.load(new URL(uri));
                    } catch (Exception e1) {
                      return null;
                    }
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

  private PublicKey getPublicKey(
      MessageContext msgCtxt,
      final String keyEncryptionAlgorithm,
      final Consumer<String> onKeySelected)
      throws Exception {
    String publicKeyString = _getOptionalString(msgCtxt, "public-key");
    return (publicKeyString != null)
        ? KeyUtil.decodePublicKey(publicKeyString)
        : getPublicKeyFromJwks(msgCtxt, keyEncryptionAlgorithm, onKeySelected);
  }

  private static JWKMatcher.Builder matcherBuilder(String algorithmName) throws Exception {
    if (algorithmName.startsWith("RSA")) return new JWKMatcher.Builder().keyType(KeyType.RSA);
    if (algorithmName.startsWith("ECDH")) return new JWKMatcher.Builder().keyType(KeyType.EC);

    throw new IllegalStateException("unsupported key encryption algorithm.");

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
    KeyType kt = randomItem.getKeyType();
    return (kt == KeyType.RSA)
        ? randomItem.toRSAKey().toPublicKey()
        : randomItem.toECKey().toPublicKey();
  }

  private PublicKey getPublicKeyFromJwks(
      final MessageContext msgCtxt,
      final String algorithmName,
      final Consumer<String> onKeySelected)
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
      // find key with specific kid, and an appropriate algorithm. Ignore use.
      List<JWK> filtered =
          new JWKSelector(matcherBuilder(algorithmName).keyID(keyId).build()).select(jwks);

      if (filtered.size() == 0) {
        throw new IllegalStateException(
            String.format("a suitable key with kid '%s' was not found.", keyId));
      }
      if (filtered.size() == 1) {
        return selectKey(filtered, onKeySelected);
      }
      throw new IllegalStateException(
          String.format("more than one key with kid '%s' found.", keyId));
    }

    // select any key with the appropriate algorithm
    List<JWK> filtered =
        new JWKSelector(matcherBuilder(algorithmName).build())
            .select(jwks).stream()
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

  protected JWEEncrypter getEncrypter(PolicyConfig policyConfig) throws Exception {
    if (policyConfig.algorithmFamily == AlgorithmFamily.SYMMETRIC) {
      return new AESEncrypter(policyConfig.secretKey);
    }
    if (policyConfig.algorithmFamily == AlgorithmFamily.ASYMMETRIC) {
      return (policyConfig.publicKey instanceof RSAPublicKey)
          ? new RSAEncrypter((RSAPublicKey) policyConfig.publicKey)
          : new ECDHEncrypter((ECPublicKey) policyConfig.publicKey);
    }

    throw new IllegalStateException("unsupported key encryption algorithm family.");
  }

  static class PolicyConfig {
    public boolean debug;
    public String keyEncryptionAlgorithm;
    public AlgorithmFamily algorithmFamily;
    public String contentEncryptionAlgorithm;
    public PublicKey publicKey;
    public byte[] secretKey;

    public String payload;
    public String payloadVariable;
    public String header;
    public String keyId;
    public String crit;
    public String outputVar;
    public boolean compress;
    public boolean generateId;

    /* only for JWT */
    public int expiry;
    public int notBefore;

    /* only for JWE */
    public String serializationFormat;

    public PolicyConfig() {
      algorithmFamily = AlgorithmFamily.NOTSET;
    }
  }

  PolicyConfig getPolicyConfig(MessageContext msgCtxt) throws Exception {
    PolicyConfig config = new PolicyConfig();
    config.keyEncryptionAlgorithm = getKeyEncryption(msgCtxt);
    if (isSymmetricKek(config.keyEncryptionAlgorithm)) {
      config.secretKey = getSecretKey(msgCtxt);
      config.algorithmFamily = AlgorithmFamily.SYMMETRIC;
    } else {
      config.publicKey =
          getPublicKey(
              msgCtxt,
              config.keyEncryptionAlgorithm,
              kid -> {
                msgCtxt.setVariable(varName("selected_key_id"), kid);
                config.keyId = kid;
              });
      config.algorithmFamily = AlgorithmFamily.ASYMMETRIC;
    }
    config.contentEncryptionAlgorithm = getContentEncryption(msgCtxt);
    if (config.keyId == null) config.keyId = _getOptionalString(msgCtxt, "key-id");
    config.payloadVariable = _getOptionalString(msgCtxt, "payload-variable");
    config.payload = _getOptionalString(msgCtxt, "payload");
    config.serializationFormat = _getOptionalString(msgCtxt, "serialization-format");
    config.header = _getOptionalString(msgCtxt, "header");
    config.crit = _getOptionalString(msgCtxt, "crit");
    config.outputVar = _getStringProp(msgCtxt, "output", varName("output"));
    config.expiry = getExpiry(msgCtxt);
    config.notBefore = getNotBefore(msgCtxt);
    config.generateId = _getBooleanProperty(msgCtxt, "generate-id", false);
    config.compress = _getBooleanProperty(msgCtxt, "compress", false);
    if ((config.payload != null && config.payloadVariable != null)
        || (config.payload == null && config.payloadVariable == null)) {
      throw new IllegalStateException("specify one of payload or payload-variable.");
    }
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
