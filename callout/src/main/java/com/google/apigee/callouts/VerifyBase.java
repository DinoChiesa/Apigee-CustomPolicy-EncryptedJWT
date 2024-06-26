// VerifyJwe.java
//
// handles verifying JWE, which are not treated as JWT.
// For full details see the Readme accompanying this source file.
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
import com.google.apigee.util.KeyUtil;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class VerifyBase extends EncryptedJoseBase implements Execution {
  public VerifyBase(Map properties) {
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
    if (critHeaders == null) return new HashSet<String>(); // empty set

    return new HashSet<String>(Arrays.asList(critHeaders.split("\\s*,\\s*")));
  }

  abstract void decrypt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception;

  protected JWEDecrypter getDecrypter(PolicyConfig policyConfig) throws Exception {
    if (policyConfig.algorithmFamily == AlgorithmFamily.ASYMMETRIC) {
      return (policyConfig.privateKey instanceof RSAPrivateKey)
          ? new RSADecrypter(policyConfig.privateKey, policyConfig.deferredCritHeaders)
          : new ECDHDecrypter(
              (ECPrivateKey) policyConfig.privateKey, policyConfig.deferredCritHeaders);
    }

    if (policyConfig.algorithmFamily == AlgorithmFamily.SYMMETRIC) {
      return new AESDecrypter(policyConfig.secretKey);
    }

    throw new IllegalStateException("unsupported key encryption algorithm family.");
  }

  static class PolicyConfig {
    public boolean debug;
    public String keyEncryptionAlgorithm;
    public AlgorithmFamily algorithmFamily;
    public String contentEncryptionAlgorithm;
    public PrivateKey privateKey;
    public byte[] secretKey;
    public Set<String> deferredCritHeaders;
    public String source;

    public PolicyConfig() {
      algorithmFamily = AlgorithmFamily.NOTSET;
    }
  }

  PolicyConfig getPolicyConfiguration(MessageContext msgCtxt) throws Exception {
    PolicyConfig config = new PolicyConfig();
    config.keyEncryptionAlgorithm = getKeyEncryption(msgCtxt);
    config.contentEncryptionAlgorithm = getContentEncryption(msgCtxt);
    if (isSymmetricKek(config.keyEncryptionAlgorithm)) {
      config.secretKey = getSecretKey(msgCtxt);
      config.algorithmFamily = AlgorithmFamily.SYMMETRIC;
    } else {
      config.privateKey = getPrivateKey(msgCtxt);
      config.algorithmFamily = AlgorithmFamily.ASYMMETRIC;
    }
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
      decrypt(policyConfig, msgCtxt);
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
