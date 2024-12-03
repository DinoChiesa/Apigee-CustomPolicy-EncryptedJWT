// TestEncrypt.java
//
// Copyright © 2018-2024 Google LLC
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

import com.apigee.flow.execution.ExecutionResult;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.RestrictedResourceRetriever;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestEncrypt extends CalloutTestBase {

  /*
   * TODO: remove external dependencies from the tests.
   **/

  // The address of the JWKS Service offering keys for testing purposes.
  private static final String JWKS_BASE_URL = "https://jwks-service.dinochiesa.net";

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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNotNull(output);
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("ejwt_output");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("ejwt_output");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNotNull(output);
    String id = msgCtxt.getVariableAsString("ejwt_jti");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNotNull(output);
    String id = msgCtxt.getVariableAsString("ejwt_jti");
    Assert.assertNotNull(id);
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt7_JWE_compressed() {
    int[] lengths = new int[2];
    msgCtxt.setVariable("random1", StringGen.randomString(28));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    for (int i = 0; i < 2; i++) {
      Map<String, String> properties = new HashMap<String, String>();
      properties.put("testname", "encrypt7");
      properties.put("public-key", publicKey1);
      properties.put("key-encryption", "RSA-OAEP");
      properties.put("content-encryption", "A256GCM");
      properties.put("payload", jwt1);
      properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
      properties.put("debug", "true");
      properties.put("compress", (i == 1) ? "true" : "false");

      GenerateJwe callout = new GenerateJwe(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // check result and output
      reportThings("jwe", properties);
      Assert.assertEquals(result, ExecutionResult.SUCCESS);
      // retrieve output
      String error = msgCtxt.getVariableAsString("jwe_error");
      Assert.assertNull(error);
      String output = msgCtxt.getVariableAsString("jwe_output");
      Assert.assertNotNull(output);
      lengths[i] = output.length();
    }
    // with compression the output should be shorter
    Assert.assertTrue(lengths[0] > lengths[1]);
  }

  @Test()
  public void encrypt8_JWE_via_JWKS() throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();

    RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(4000, 3000, 1024);
    Resource resource =
        resourceRetriever.retrieveResource(new URL(JWKS_BASE_URL + "/keyids?type=rsa"));
    Type type = new TypeToken<Map<String, Object>>() {}.getType();
    Map<String, Object> json = new Gson().fromJson(resource.getContent(), type);

    @SuppressWarnings("unchecked")
    List<Object> ids = (List<Object>) json.get("ids");
    String selectedKeyId = (String) ids.get(0);

    properties.put("testname", "encrypt8");
    properties.put("jwks-uri", JWKS_BASE_URL + "/.well-known/jwks.json");
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);

    String encodedHeader = output.split("\\.")[0];
    String headerInJsonForm =
        new String(Base64.getDecoder().decode(encodedHeader), StandardCharsets.UTF_8);
    System.out.printf("JSON: %s\n", headerInJsonForm);

    json = new Gson().fromJson(headerInJsonForm, type);
    String cty = (String) json.get("cty");
    Assert.assertNotNull(cty);
    Assert.assertEquals(cty, "JWT");
  }

  @Test()
  public void encrypt9_JWE_via_JWKS_no_keyid() {
    Map<String, String> properties = new HashMap<String, String>();

    properties.put("testname", "encrypt9");
    properties.put("jwks-uri", JWKS_BASE_URL + "/.well-known/jwks.json");
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String selectedKeyId = msgCtxt.getVariableAsString("jwe_selected_key_id");
    Assert.assertNotNull(selectedKeyId);
    String output = msgCtxt.getVariableAsString("jwe_output");

    String jweHeader = msgCtxt.getVariableAsString("jwe_header");
    Assert.assertNotNull(jweHeader);
    Assert.assertTrue(jweHeader.indexOf("\"kid\"") > 0);
  }

  @Test()
  public void encrypt10_JWE_neither_JWKS_nor_publickey() {
    Map<String, String> properties = new HashMap<String, String>();

    properties.put("testname", "encrypt10");
    // properties.put("jwks-uri", "...."); // not provided
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "specify one of {public-key, jwks, jwks-uri}.");
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt11_JWE_bad_JWKS() throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();

    RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(12000, 11000);
    Resource resource =
        resourceRetriever.retrieveResource(new URL(JWKS_BASE_URL + "/keyids?type=rsa"));
    Type type = new TypeToken<Map<String, Object>>() {}.getType();
    Map<String, Object> json = new Gson().fromJson(resource.getContent(), type);
    @SuppressWarnings("unchecked")
    List<Object> ids = (List<Object>) json.get("ids");
    String selectedKeyId = (String) ids.get(0);

    properties.put("testname", "encrypt12");
    properties.put("jwks-uri", JWKS_BASE_URL + "/keyids"); // this is not a JWKS
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);

    Assert.assertTrue(error.matches("a suitable key with kid '[a-z0-9]{4,14}' was not found."));
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt12_JWE_RSA_static_JWKS()
      throws MalformedURLException, IOException, ParseException {
    RestrictedResourceRetriever resourceRetriever =
        new DefaultResourceRetriever(14000, 11000, 10240);
    Resource resource =
        resourceRetriever.retrieveResource(new URL(JWKS_BASE_URL + "/.well-known/jwks.json"));
    String jwksContent = resource.getContent();

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt12");
    properties.put("jwks", "{jwksContent}");
    properties.put("key-encryption", "RSA-OAEP");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("jwksContent", jwksContent);
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);
    String jweHeader = msgCtxt.getVariableAsString("jwe_header");
    Assert.assertNotNull(jweHeader);
    Assert.assertTrue(jweHeader.indexOf("\"kid\"") > 0);
  }

  @Test()
  public void encrypt13_JWE_EC_JWKS() throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt13");
    properties.put("jwks-uri", JWKS_BASE_URL + "/.well-known/jwks.json");
    properties.put("key-encryption", "ECDH-ES+A128KW");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    // properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");
    // properties.put("key-id", selectedKeyId);

    // msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);
    String jweHeader = msgCtxt.getVariableAsString("jwe_header");
    Assert.assertNotNull(jweHeader);
    Assert.assertTrue(jweHeader.indexOf("\"kid\"") > 0);
    String alg = msgCtxt.getVariableAsString("jwe_alg");
    Assert.assertEquals(alg, "ECDH-ES+A128KW");
    String enc = msgCtxt.getVariableAsString("jwe_enc");
    Assert.assertEquals(enc, "A256GCM");
  }

  @Test()
  public void encrypt14_JWE_EC_PEM() throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt14");
    properties.put("public-key", ecPublicKey1);
    properties.put("key-encryption", "ECDH-ES+A128KW");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", "The quick brown fox jumped over the lazy dog.");
    properties.put("debug", "true");

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);
    String jweHeader = msgCtxt.getVariableAsString("jwe_header");
    Assert.assertNotNull(jweHeader);
    Assert.assertTrue(jweHeader.indexOf("\"kid\"") < 0);
    String alg = msgCtxt.getVariableAsString("jwe_alg");
    Assert.assertEquals(alg, "ECDH-ES+A128KW");
    String enc = msgCtxt.getVariableAsString("jwe_enc");
    Assert.assertEquals(enc, "A256GCM");
  }

  @Test()
  public void encrypt15_Wrong_KeyType_JWKS()
      throws MalformedURLException, IOException, ParseException {

    RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(4000, 3000, 1024);
    Resource resource =
        resourceRetriever.retrieveResource(new URL(JWKS_BASE_URL + "/keyids?type=rsa"));
    Type type = new TypeToken<Map<String, Object>>() {}.getType();
    Map<String, Object> json = new Gson().fromJson(resource.getContent(), type);
    @SuppressWarnings("unchecked")
    List<Object> ids = (List<Object>) json.get("ids");
    String selectedKeyId = (String) ids.get(0);

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt15");
    properties.put("key-id", selectedKeyId);
    properties.put("jwks-uri", JWKS_BASE_URL + "/.well-known/jwks.json");
    properties.put("key-encryption", "ECDH-ES+A128KW");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    // properties.put("header", "{ \"p1.org\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    // msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertTrue(error.matches("a suitable key with kid '[a-z0-9]{4,14}' was not found."));
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNull(output); // because failed
  }

  @Test()
  public void encrypt16_JWE_Wrong_KeyType_PEM()
      throws MalformedURLException, IOException, ParseException {

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt16");
    properties.put("public-key", publicKey1); // rsa key
    properties.put("key-encryption", "ECDH-ES+A128KW");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("debug", "true");

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertTrue(
        error.matches(
            "^The \"?ECDH-ES\\+A128KW\"? algorithm is not supported by the JWE encrypter.+$"));
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNull(output); // because failed
  }

  @Test()
  public void encrypt17_JWT_Wrong_KeyType_PEM() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt17");
    properties.put("public-key", ecPublicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload",
        "{ \"sub\": \"dino\", \"something\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertTrue(
        error.matches(
            "^The \"?RSA-OAEP-256\"? algorithm is not supported by the JWE encrypter.+$"));
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt18_JWT_ECDH_PEM_success() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt18");
    properties.put("public-key", ecPublicKey1);
    properties.put("key-encryption", "ECDH-ES+A256KW");
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload", "{ \"sub\": \"dino\", \"uid\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt20_JWE_EC_PEM_FullSerialization()
      throws MalformedURLException, IOException, ParseException {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt20");
    properties.put("public-key", ecPublicKey1);
    properties.put("key-encryption", "ECDH-ES+A128KW");
    properties.put("content-encryption", "A256GCM");
    properties.put("serialization-format", "full");
    properties.put("payload", "The quick brown fox jumped over the lazy dog.");
    properties.put("debug", "true");

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String jweOutput = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(jweOutput);

    // parse jweOutput as JSON
    Type type = new TypeToken<Map<String, Object>>() {}.getType();
    Map<String, String> map = new Gson().fromJson(jweOutput, type);
    List<String> list = Arrays.asList("protected", "encrypted_key", "iv", "ciphertext", "tag");
    for (String key : list) {
      String value = map.get(key);
      System.out.printf("  %s = %s\n", key, value);
      Assert.assertNotNull(value);
    }

    String jweHeader = msgCtxt.getVariableAsString("jwe_header");
    Assert.assertNotNull(jweHeader);
    Assert.assertTrue(jweHeader.indexOf("\"kid\"") < 0);
    String alg = msgCtxt.getVariableAsString("jwe_alg");
    Assert.assertEquals(alg, "ECDH-ES+A128KW");
    String enc = msgCtxt.getVariableAsString("jwe_enc");
    Assert.assertEquals(enc, "A256GCM");
  }

  @Test()
  public void encrypt21_JWT_Unsupported_Serialization_Format() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt21");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("serialization-format", "compact"); // not supported
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload",
        "{ \"sub\": \"dino\", \"something\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "serialization-format is not supported for JWT.");

    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt22_missing_payload() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt22");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "specify one of payload or payload-variable.");
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt24_both_payload_and_payload_variable() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt24");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", "foobar");
    properties.put("payload-variable", "var1");
    msgCtxt.setVariable("var1", StringGen.randomString(28));

    GenerateEncryptedJwt callout = new GenerateEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "specify one of payload or payload-variable.");
    String output = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNull(output);
  }

  @Test()
  public void encrypt25_payload_variable_string() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt25");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload-variable", "var1");
    msgCtxt.setVariable("var1", StringGen.randomString(28));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt26_payload_variable_bytearray() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt26");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload-variable", "var1");
    properties.put("debug", "true");

    byte[] b = new byte[400];
    new Random().nextBytes(b);
    msgCtxt.setVariable("var1", b);

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(output);
  }

  @Test()
  public void encrypt27_payload_variable_bytearray_json_ser() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt27");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload-variable", "var1");
    properties.put("serialization-format", "json");
    properties.put("debug", "true");

    final int PAYLOAD_LENGTH = 400;
    byte[] b = new byte[PAYLOAD_LENGTH];
    new Random().nextBytes(b);
    msgCtxt.setVariable("var1", b);

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String jweOutput = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNotNull(jweOutput);

    // parse jweOutput as JSON
    Type type = new TypeToken<Map<String, Object>>() {}.getType();
    Map<String, String> map = new Gson().fromJson(jweOutput, type);
    List<String> list = Arrays.asList("protected", "encrypted_key", "iv", "ciphertext", "tag");
    for (String key : list) {
      String value = map.get(key);
      System.out.printf("  %s = %s\n", key, value);
      Assert.assertNotNull(value);
    }

    // This is a weak test, but... with encryption and base64 encoding the
    // ciphertext should be larger.
    String ciphertext = map.get("ciphertext");
    Assert.assertTrue(PAYLOAD_LENGTH < ciphertext.length());
  }

  @Test()
  public void encrypt28_JWE_with_expiry() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "encrypt28");
    properties.put("public-key", publicKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", "this-is-the-payload-to-encrypt-" + StringGen.randomString(28));
    properties.put("debug", "true");
    properties.put("expiry", "1h");

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals("unsupported property for GenerateJwe (expiry).", error);
    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNull(output);
  }
}
