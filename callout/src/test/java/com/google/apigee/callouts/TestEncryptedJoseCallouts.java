// TestEncryptedJoseCallouts.java
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
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.RestrictedResourceRetriever;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import mockit.Mock;
import mockit.MockUp;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class TestEncryptedJoseCallouts extends CalloutTestBase {

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
  public void encrypt1() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt1");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload",
        "{ \"sub\": \"dino\", \"something\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(output);
  }

  static class StringGen {
    public static final char[] CHARSET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    private static final Random random = new SecureRandom();

    public static String randomString(char[] characterSet, int length) {
      char[] result = new char[length];
      for (int i = 0; i < result.length; i++) {
        // picks a random index out of character set > random character
        int randomCharIndex = random.nextInt(characterSet.length);
        result[i] = characterSet[randomCharIndex];
      }
      return new String(result);
    }

    public static String randomString(int length) {
      return randomString(CHARSET, length);
    }
  }

  @Test()
  public void encrypt2_with_expiry() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt2");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", "{ \"sub\": \"dino\", \"rand\" : \"{random1}\"}");
    properties.put("debug", "true");
    properties.put("expiry", "1h");
    properties.put("not-before", "1m");

    msgCtxt.setVariable("random1", StringGen.randomString(28));

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt3_missing_ContentEncryption() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt3");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    // properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload", "{ \"sub\": \"dino\", \"unk\" : \"600c3efa-e48e-49c8-b6d9-e6bb9b94ad52\"}");
    properties.put("debug", "true");
    properties.put("expiry", "1h");
    properties.put("not-before", "1m");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertEquals(error, "missing content-encryption.");
  }

  @Test()
  public void encrypt4_RSA_OAEP() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt4");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A128GCM");
    properties.put("payload", "{ \"sub\": \"dino\", \"unk\" : \"{random1}\"}");
    properties.put("header", "{ \"p1.org\": \"{random2}\"}");
    properties.put("debug", "true");
    properties.put("expiry", "1h");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt5_with_id() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt5");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A128GCM");
    properties.put("payload", "{ \"sub\": \"dino\", \"rand\" : \"{random1}\"}");
    properties.put("generate-id", "true");
    properties.put("debug", "true");
    properties.put("expiry", "1h");

    msgCtxt.setVariable("random1", StringGen.randomString(28));

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(output);
    String id = msgCtxt.getVariable("ejwt_jti");
    Assert.assertNotNull(id);
  }

  @Test()
  public void encrypt_with_header_and_crit() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt_with_header_and_crit");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A128GCM");
    properties.put("payload", "{ \"sub\": \"dino\", \"rand\" : \"{random1}\"}");
    properties.put("header", "{ \"foo\" : \"{greeting}\"}");
    properties.put("crit", "foo");
    properties.put("generate-id", "true");
    properties.put("debug", "true");
    properties.put("expiry", "1h");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("greeting", "hello");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("ejwt_output");
    Assert.assertNotNull(output);
    String id = msgCtxt.getVariable("ejwt_jti");
    Assert.assertNotNull(id);
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
  public void encrypt6_JWE() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt6");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("jwe_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt7_JWE_compressed() {
    int[] lengths = new int[2];
    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    for (int i=0; i< 2; i++) {
      Map<String, String> properties = new HashMap<String, String>();
      properties.put("testname", "encrypt7");
      properties.put("public-key", publicKey1);
      properties.put("key-encryption", "RSA-OAEP");
      properties.put("content-encryption", "A256GCM");
      properties.put("payload", jwt1);
      properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
      properties.put("debug", "true");
      properties.put("compress", (i==1)? "true": "false");

      GenerateJwe callout = new GenerateJwe(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // check result and output
      reportThings(properties);
      Assert.assertEquals(result, ExecutionResult.SUCCESS);
      // retrieve output
      String error = msgCtxt.getVariable("jwe_error");
      Assert.assertNull(error);
      String output = msgCtxt.getVariable("jwe_output");
      Assert.assertNotNull(output);
      lengths[i] = output.length();
    }
    // with compression the output should be shorter
    Assert.assertTrue(lengths[0] > lengths[1]);
  }


  @Test()
  public void encrypt8_JWE_via_JWKS() throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();

    RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(4000,3000,1024);
    Resource resource = resourceRetriever.retrieveResource(new URL("https://jwks-service.appspot.com/keyids?type=rsa"));
    JSONObject json = JSONObjectUtils.parse(resource.getContent());
    JSONArray ids = JSONObjectUtils.getJSONArray(json, "ids");
    String selectedKeyId = (String) ids.get(0);

    properties.put("testname", "encrypt8");
    properties.put("jwks-uri", "https://jwks-service.appspot.com/.well-known/jwks.json");
    properties.put("key-id", selectedKeyId);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariable("jwe_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt9_JWE_via_JWKS_fail_no_keyid() {
    Map<String, String> properties = new HashMap<String, String>();

    properties.put("testname", "encrypt9");
    properties.put("jwks-uri", "https://jwks-service.appspot.com/.well-known/jwks.json");
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "key-id resolves to null or empty.");
    String output = msgCtxt.getVariable("jwe_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt10_JWE_no_JWKS_or_publickey() {
    Map<String, String> properties = new HashMap<String, String>();

    properties.put("testname", "encrypt10");
    //properties.put("jwks-uri", "https://jwks-service.appspot.com/.well-known/jwks.json");
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "specify one of public-key or jwks-uri.");
    String output = msgCtxt.getVariable("jwe_output");
    Assert.assertNull(output);
  }


  @Test()
  public void encrypt11_JWE_bad_JWKS() throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();

    RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(4000,3000,1024);
    Resource resource = resourceRetriever.retrieveResource(new URL("https://jwks-service.appspot.com/keyids?type=rsa"));
    JSONObject json = JSONObjectUtils.parse(resource.getContent());
    JSONArray ids = JSONObjectUtils.getJSONArray(json, "ids");
    String selectedKeyId = (String) ids.get(0);

    properties.put("testname", "encrypt8");
    properties.put("jwks-uri", "https://jwks-service.appspot.com/keyids"); // not a JWKS
    properties.put("key-id", selectedKeyId);
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings(properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariable("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "java.text.ParseException: Missing required \"keys\" member");
    String output = msgCtxt.getVariable("jwe_output");
    Assert.assertNull(output);
  }

}
