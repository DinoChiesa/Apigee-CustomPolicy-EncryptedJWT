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
import java.util.Map;

public class GenerateJwe extends GenerateBase implements Execution {
  public GenerateJwe(Map properties) {
    super(properties);
  }

  String getVarPrefix() {
    return "jwe_";
  }
  ;

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
    msgCtxt.setVariable(varName("header"), toString(header.toJSONObject()));

    JWEObject jwe = new JWEObject(header, new Payload(policyConfig.payload));
    JWEEncrypter encrypter = getEncrypter(policyConfig);

    jwe.encrypt(encrypter);
    String serialized = jwe.serialize();
    msgCtxt.setVariable(policyConfig.outputVar, serialized);
  }
}
