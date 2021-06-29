// TestDecrypt.java
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

import com.apigee.flow.execution.ExecutionResult;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestDecrypt extends CalloutTestBase {

  @Test()
  public void decrypt1() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt1");
    properties.put("private-key", privateKey2);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwt1);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
  }

  @Test()
  public void decrypt2_with_CEK() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt2");
    properties.put("private-key", privateKey2);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("source", "message.content");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", jwt1);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertEquals(error, "JWT uses unacceptable Content Encryption Algorithm.");
  }

  @Test()
  public void decrypt3_with_KEK() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt3");
    properties.put("private-key", privateKey2);
    properties.put("key-encryption", "dir"); // not supported
    properties.put("content-encryption", "A256GCM");
    properties.put("source", "message.content");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", jwt1);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertEquals(error, "that key-encryption algorithm name is unsupported.");
  }

  @Test()
  public void decrypt4_with_expiry() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt4");
    properties.put("private-key", privateKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("source", "message.content");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", jwt2);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertEquals(error, "JWT is expired.");
  }

  @Test()
  public void decrypt5_jwe() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt5");
    properties.put("private-key", privateKey3);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("source", "message.content");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", jwe1);

    VerifyJwe callout = new VerifyJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertNull(error);
    String cty = msgCtxt.getVariable("jwe_header_cty");
    Assert.assertEquals(cty, "JWT");
    String payload = msgCtxt.getVariable("jwe_payload");
    Assert.assertNotNull(payload);
    Assert.assertTrue(payload.startsWith("eyJhbGciOiJSUzI1NiIsImtpZCI6"));
  }

  @Test()
  public void decrypt6_jwe_wrongkey() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt6");
    properties.put("private-key", privateKey1);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("source", "message.content");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", jwe1);

    VerifyJwe callout = new VerifyJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertEquals(error, "Decryption error");
  }

  @Test()
  public void decrypt7_with_max_lifetime() {

    /* ----- Generate the JWT ----- */
    Map<String, String> properties1 = new HashMap<String, String>();
    properties1.put("testname", "decrypt7");
    properties1.put("public-key", publicKey1);
    properties1.put("key-encryption", "RSA-OAEP-256");
    properties1.put("content-encryption", "A128GCM");
    properties1.put("payload", "{ \"sub\": \"dino\", \"aud\" : \"{aud-value}\"}");
    properties1.put("generate-id", "false");
    properties1.put("debug", "true");
    // The not-before is 5m in the past. The net total lifetime is 10m.
    // The net *usable* lifetime is just 5m.
    properties1.put("not-before", "-5m");
    properties1.put("expiry", "5m");
    msgCtxt.setVariable("aud-value", "146B30DD-5338-472D-9357-EF6545C146AF");
    GenerateEncryptedJwt callout1 = new GenerateEncryptedJwt(properties1);
    ExecutionResult result1 = callout1.execute(msgCtxt, exeCtxt);
    reportThings(properties1);
    Assert.assertEquals(result1, ExecutionResult.SUCCESS);
    String encryptedJwt = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(encryptedJwt);

    /* ----- Verify, without enforcing a max lifetime ----- */
    Map<String, String> properties2 = new HashMap<String, String>();
    properties2.put("testname", "decrypt7");
    properties2.put("private-key", privateKey1);
    properties2.put("key-encryption", "RSA-OAEP-256");
    properties2.put("source", "message.content");
    properties2.put("debug", "true");
    msgCtxt.setVariable("message.content", encryptedJwt);
    VerifyEncryptedJwt callout2 = new VerifyEncryptedJwt(properties2);
    ExecutionResult result2 = callout2.execute(msgCtxt, exeCtxt);
    reportThings(properties2);
    Assert.assertEquals(result2, ExecutionResult.SUCCESS);
    String error2 = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error2);

    /* ----- Verify, enforcing a max lifetime, which is exceeded ----- */
    Map<String, String> properties3 = new HashMap<String, String>();
    properties3.put("testname", "decrypt7");
    properties3.put("private-key", privateKey1);
    properties3.put("key-encryption", "RSA-OAEP-256");
    properties3.put("source", "message.content");
    properties3.put("max-lifetime", "8m");
    properties3.put("debug", "true");
    msgCtxt.setVariable("message.content", encryptedJwt);
    VerifyEncryptedJwt callout3 = new VerifyEncryptedJwt(properties3);
    ExecutionResult result3 = callout3.execute(msgCtxt, exeCtxt);
    reportThings(properties3);
    Assert.assertEquals(result3, ExecutionResult.ABORT);
    String error3 = msgCtxt.getVariable("ejwt_error");
    Assert.assertNotNull(error3);
    Assert.assertEquals(error3, "the JWT has a lifetime that exceeds the configured limit.");

    /* ----- Verify, enforcing a max lifetime, which is NOT exceeded ----- */
    Map<String, String> properties4 = new HashMap<String, String>();
    properties4.put("testname", "decrypt7");
    properties4.put("private-key", privateKey1);
    properties4.put("key-encryption", "RSA-OAEP-256");
    properties4.put("source", "message.content");
    properties4.put("max-lifetime", "18m");
    properties4.put("debug", "true");
    msgCtxt.setVariable("message.content", encryptedJwt);
    VerifyEncryptedJwt callout4 = new VerifyEncryptedJwt(properties4);
    ExecutionResult result4 = callout4.execute(msgCtxt, exeCtxt);
    reportThings(properties4);
    Assert.assertEquals(result4, ExecutionResult.SUCCESS);
    String error4 = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error4);
  }

  @Test()
  public void decrypt8_no_expiry_max_lifetime() {

    Map<String, String> properties1 = new HashMap<String, String>();
    properties1.put("testname", "decrypt8");
    properties1.put("public-key", publicKey1);
    properties1.put("key-encryption", "RSA-OAEP-256");
    properties1.put("content-encryption", "A128GCM");
    properties1.put("payload", "{ \"sub\": \"dino\", \"aud\" : \"{aud-value}\"}");
    properties1.put("generate-id", "false");
    properties1.put("debug", "true");
    // no expiry
    msgCtxt.setVariable("aud-value", "146B30DD-5338-472D-9357-EF6545C146AF");

    GenerateEncryptedJwt callout1 = new GenerateEncryptedJwt(properties1);
    ExecutionResult result1 = callout1.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties1);
    Assert.assertEquals(result1, ExecutionResult.SUCCESS);
    String encryptedJwt = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(encryptedJwt);

    // not enforce max lifetime
    Map<String, String> properties2 = new HashMap<String, String>();
    properties2.put("testname", "decrypt7");
    properties2.put("private-key", privateKey1);
    properties2.put("key-encryption", "RSA-OAEP-256");
    properties2.put("source", "message.content");
    properties2.put("max-lifetime", "8m");
    properties2.put("debug", "true");

    msgCtxt.setVariable("message.content", encryptedJwt);

    VerifyEncryptedJwt callout2 = new VerifyEncryptedJwt(properties2);
    ExecutionResult result2 = callout2.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties2);
    Assert.assertEquals(result2, ExecutionResult.ABORT);
    // retrieve output
    String error2 = msgCtxt.getVariable("ejwt_error");
    Assert.assertNotNull(error2);
    Assert.assertEquals(
        error2, "the JWT has an unlimited lifetime which exceeds the configured limit.");
  }
}
