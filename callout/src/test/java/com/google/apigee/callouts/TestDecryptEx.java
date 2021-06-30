// TestDecryptEx.java
//
// Copyright (c) 2018-2021 Google LLC
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
// Note:
// If you use the Oracle JDK to run tests, this test, which does
// 256-bit crypto, requires the Unlimited Strength JCE.
//
// Without it, you may get an exception while running this test:
//
// java.security.InvalidKeyException: Illegal key size
//         at javax.crypto.Cipher.checkCryptoPerm(Cipher.java:1039)
//         ....
//
// See http://stackoverflow.com/a/6481658/48082
//
// If you use OpenJDK to run the tests, then it's not an issue.
// In that JDK, there's no restriction on key strength.
//

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;
import com.google.gson.Gson;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TestDecryptEx extends CalloutTestBase {

  private static final String ejwt1 =
      "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.Wf77ZGSTukkVSQHRAivihrx3nMcmG74a58glykZ2jxkvfPk7NqptIOwbxU3JRocwEIS9dpX1eB_w8J2J0j6NXR4Q8gsoEqSu5tHaoP5vh9-gjfR4PtvsH0gttbloDxvivxhJOlLUGw6q1VwpVc_rzmvW6eczxXZCcInW04hDX84s8e1XfUBTCUduwYvlprwt5mBKt9FE-P4a8a1PdBXy3lLJvIiJCfmB_LQAlCM5bE0t5dc-bAvL--D-UL8-REbUXWjUly4Ro0KfPcJ1yODF5z8Mc2-BSHssB7lc9_S08VtjqaAIkqoAXkacohLfza6tsD1u0G7MtzOyu0Ww_30nSQ.FiIYOmXZr1UN0zAH.7s67r_9mjcmlSFZiMNwIePT9a4b8UEdFLwpSNtGv7gvly-JYcnf0RnwusX19RENRx7lKjLdl5SJC2pP9sMEaWUjMvg.oTT4c10mabqe2N4rM7MUgQ";

  public static String getEncryptWithPublicKey(String payload) {
    JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
    EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;
    try {
      RSAPublicKey key = readPublicKey();
      JWEObject jwe = new JWEObject(new JWEHeader(alg, encryptionMethod), new Payload(payload));
      jwe.encrypt(new RSAEncrypter(key));
      return jwe.serialize();
    } catch (Exception e) {
      System.out.printf("ERROR: %s\n", e.getMessage());
    }
    return null;
  }

  public static RSAPublicKey readPublicKey()
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    String publicKeyPEM =
        publicKey1
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replaceAll(System.lineSeparator(), "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
    byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) keyFactory.generatePublic(spec);
  }

  @Test()
  public void decrypt1() {
    Map<String, Object> map1 = new HashMap<String, Object>();
    map1.put("tax-status", "01");
    map1.put("is-new-version", "FTM");
    map1.put("first-pan", "BDJPA0600D");
    String payload = new Gson().toJson(map1);

    String jwt = getEncryptWithPublicKey(payload);
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt1");
    properties.put("private-key", privateKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
  }

  @Test()
  public void decrypt2() {

    String jwt = ejwt1;
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt2");
    properties.put("private-key", privateKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
  }

  @Test()
  public void decrypt2_fail() {

    // replace final two characters of tag with rubbish
    String jwt = ejwt1.substring(0, ejwt1.length() - 2) + "xx";
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt2");
    properties.put("private-key", privateKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "AES/GCM/NoPadding decryption failed: Tag mismatch!");
  }

  @Test()
  public void decrypt1_fail() {
    Map<String, Object> map1 = new HashMap<String, Object>();
    map1.put("tax-status", "01");
    map1.put("is-new-version", "FTM");
    map1.put("first-pan", "BDJPA0600D");
    String payload = new Gson().toJson(map1);

    String jwt = getEncryptWithPublicKey(payload);
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt1_fail");
    properties.put("private-key", privateKey3);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "Decryption error");
  }
}
