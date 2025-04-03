// GenerateJwe.java
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

import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class GenerateJwe extends GenerateBase implements Execution {
  public GenerateJwe(Map properties) {
    super(properties);
  }

  String getVarPrefix() {
    return "jwe_";
  }

  public static final List<String> serializationOptions = Arrays.asList("full", "json", "compact");

  private static String convertToJson(String dotSeparatedJwe) {
    String[] substrings = dotSeparatedJwe.split("\\.");
    if (substrings.length != 5) {
      throw new IllegalStateException("internal JWE format error.");
    }
    List<String> propnames = Arrays.asList("protected", "encrypted_key", "iv", "ciphertext", "tag");
    // use JWTClaimSet.Builder to build a json
    JWTClaimsSet.Builder jsonBuilder = new JWTClaimsSet.Builder();

    for (int i = 0; i < substrings.length; i++) {
      jsonBuilder.claim(propnames.get(i), substrings[i]);
    }
    return jsonBuilder.build().toJSONObject().toString();
  }

  private static byte[] readAllBytes(InputStream inputStream) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[1024];
    while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }
    buffer.flush();
    return buffer.toByteArray();
  }

  void encrypt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception {
    if (policyConfig.serializationFormat != null) {
      policyConfig.serializationFormat = policyConfig.serializationFormat.toLowerCase();
      if (!serializationOptions.contains(policyConfig.serializationFormat)) {
        throw new IllegalStateException("unsupported serialization-format.");
      }
    }
    if (policyConfig.expiry != 0) {
      throw new IllegalStateException("unsupported property for GenerateJwe (expiry).");
    }
    if (policyConfig.notBefore != 0) {
      throw new IllegalStateException("unsupported property for GenerateJwe (not-before).");
    }
    if (policyConfig.generateId) {
      throw new IllegalStateException("unsupported property for GenerateJwe (generate-id).");
    }
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
    // headerBuilder.type(JOSEObjectType.JWT);
    if (policyConfig.header != null) {
      JSONObjectUtils.parse(policyConfig.header)
          .forEach(
              (key, value) -> {
                switch (key) {
                  case "cty":
                    headerBuilder.contentType(value.toString());
                    break;
                  default:
                    headerBuilder.customParam(key, value);
                    break;
                }
              });
    }
    if (policyConfig.keyId != null) {
      headerBuilder.keyID(policyConfig.keyId);
    }
    if (policyConfig.compress) {
      headerBuilder.compressionAlgorithm(CompressionAlgorithm.DEF);
    }

    JWEHeader header = headerBuilder.build();
    //    msgCtxt.setVariable(varName("header"), toString(header.toJSONObject()));
    msgCtxt.setVariable(varName("header"), "I-don't know");

    JWEObject jwe;

    if (policyConfig.payload != null) {
      jwe = new JWEObject(header, new Payload(policyConfig.payload));
    } else {
      Object payload = (Object) msgCtxt.getVariable(policyConfig.payloadVariable);
      if (payload instanceof byte[]) {
        jwe = new JWEObject(header, new Payload((byte[]) payload));
      } else if (payload instanceof InputStream) {
        jwe = new JWEObject(header, new Payload(readAllBytes((InputStream) payload)));
      } else if (payload instanceof String) {
        jwe = new JWEObject(header, new Payload((String) payload));
      } else {
        throw new IllegalStateException(
            String.format("unsupported payload type (%s).", payload.getClass().getName()));
      }
    }
    JWEEncrypter encrypter = getEncrypter(policyConfig);

    jwe.encrypt(encrypter);
    String serialized = jwe.serialize();

    // support the JSON
    if ("full".equals(policyConfig.serializationFormat)
        || "json".equals(policyConfig.serializationFormat)) {
      serialized = convertToJson(serialized);
    }
    msgCtxt.setVariable(policyConfig.outputVar, serialized);
  }
}
