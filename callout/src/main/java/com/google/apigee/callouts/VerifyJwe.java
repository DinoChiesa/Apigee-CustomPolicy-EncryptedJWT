// VerifyJwe.java
//
// handles verifying JWE, which are not treated as JWT.
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
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import java.util.Map;

@IOIntensive
public class VerifyJwe extends VerifyBase implements Execution {

  public VerifyJwe(Map properties) {
    super(properties);
  }

  String getVarPrefix() { return "jwe_"; };

  void decrypt(PolicyConfig policyConfig, MessageContext msgCtxt) throws Exception {
    Object v = msgCtxt.getVariable(policyConfig.source);
    if (v == null) throw new IllegalStateException("Cannot find JWE within source.");
    String jweText = (String) v;
    if (jweText.startsWith("Bearer ")) {
      jweText = jweText.substring(7);
    }
    JWEObject jwe = JWEObject.parse(jweText);
    RSADecrypter decrypter =
        new RSADecrypter(policyConfig.privateKey, policyConfig.deferredCritHeaders);
    jwe.decrypt(decrypter);
    if (jwe.getPayload() != null) {
      String payload = jwe.getPayload().toString();
      msgCtxt.setVariable(varName("payload"), payload);
    }
    if (jwe.getHeader() == null) throw new IllegalStateException("JWT included no header.");

    JWEHeader header = jwe.getHeader();
    msgCtxt.setVariable(varName("header"), header.toString());

    setVariables(null, header.toJSONObject(), msgCtxt);

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
  }
}
