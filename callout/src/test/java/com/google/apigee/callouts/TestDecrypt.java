// TestDecrypt.java
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
import java.lang.reflect.Type;
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertEquals(error, "the JWT uses an unacceptable Content Encryption Algorithm.");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertEquals(error, "that key-encryption algorithm name (dir) is unsupported.");
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
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String cty = msgCtxt.getVariableAsString("jwe_header_cty");
    Assert.assertEquals(cty, "JWT");
    String payload = msgCtxt.getVariableAsString("jwe_payload");
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
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertEquals(error, "Padding error in decryption");
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
    reportThings("ejwt", properties1);
    Assert.assertEquals(result1, ExecutionResult.SUCCESS);
    String encryptedJwt = msgCtxt.getVariableAsString("ejwt_output");
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
    reportThings("ejwt", properties2);
    Assert.assertEquals(result2, ExecutionResult.SUCCESS);
    String error2 = msgCtxt.getVariableAsString("ejwt_error");
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
    reportThings("ejwt", properties3);
    Assert.assertEquals(result3, ExecutionResult.ABORT);
    String error3 = msgCtxt.getVariableAsString("ejwt_error");
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
    reportThings("ejwt", properties4);
    Assert.assertEquals(result4, ExecutionResult.SUCCESS);
    String error4 = msgCtxt.getVariableAsString("ejwt_error");
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
    reportThings("ejwt", properties1);
    Assert.assertEquals(result1, ExecutionResult.SUCCESS);
    String encryptedJwt = msgCtxt.getVariableAsString("ejwt_output");
    Assert.assertNotNull(encryptedJwt);

    Map<String, String> properties2 = new HashMap<String, String>();
    properties2.put("testname", "decrypt8");
    properties2.put("private-key", privateKey1);
    properties2.put("key-encryption", "RSA-OAEP-256");
    properties2.put("source", "message.content");
    properties2.put("max-lifetime", "8m");
    properties2.put("debug", "true");

    msgCtxt.setVariable("message.content", encryptedJwt);

    VerifyEncryptedJwt callout2 = new VerifyEncryptedJwt(properties2);
    ExecutionResult result2 = callout2.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties2);
    Assert.assertEquals(result2, ExecutionResult.ABORT);
    // retrieve output
    String error2 = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNotNull(error2);
    Assert.assertEquals(
        error2, "the JWT has no expiry; this violates the maximum lifetime constraint.");
  }

  @Test()
  public void decrypt9_ECDH_jwe() {

    final String staticJwe =
        "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIwR2JpNHJET0pSQVREU0NSclQ5b2wxcDFkbExWS0EyQVVxcWg0aEVpcnJrIiwieSI6ImEtLUhlN2k1X25zY2VVYlRwS1dqcGVRLVBTcmRobjQ4akFkRVV1R0dfTTQifSwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMrQTEyOEtXIn0.0r6967aiuZSX0K4sm2lgkuxJYN-YPq-7CT8WeasIjqcU0UwUAYf9vg.koMsTnUA8EyfdQy7.5YzHLNCjNAQ2YXTr-4Y2Kts8uUHeLU3sCtIwvffy_scmKZSH2Qoatk4JIoQY.Z3qcRA6yRRe8QiJe6t5RFw";

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt9");
    properties.put("private-key", ecPrivateKey1);
    properties.put("key-encryption", "ECDH-ES+A128KW");
    properties.put("source", "message.content");
    // properties.put("max-lifetime", "8m");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", staticJwe);

    VerifyJwe callout = new VerifyJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNull(error);
    String payload = msgCtxt.getVariableAsString("jwe_payload");
    Assert.assertEquals(payload, "The quick brown fox jumped over the lazy dog.");
  }

  @Test()
  public void decrypt10_ECDH_jwe_unacceptable() {

    final String staticJwe =
        "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIwR2JpNHJET0pSQVREU0NSclQ5b2wxcDFkbExWS0EyQVVxcWg0aEVpcnJrIiwieSI6ImEtLUhlN2k1X25zY2VVYlRwS1dqcGVRLVBTcmRobjQ4akFkRVV1R0dfTTQifSwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMrQTEyOEtXIn0.0r6967aiuZSX0K4sm2lgkuxJYN-YPq-7CT8WeasIjqcU0UwUAYf9vg.koMsTnUA8EyfdQy7.5YzHLNCjNAQ2YXTr-4Y2Kts8uUHeLU3sCtIwvffy_scmKZSH2Qoatk4JIoQY.Z3qcRA6yRRe8QiJe6t5RFw";

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt9");
    properties.put("private-key", ecPrivateKey1);
    properties.put("key-encryption", "ECDH-ES+A256KW");
    properties.put("source", "message.content");
    properties.put("max-lifetime", "8m");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", staticJwe);

    VerifyJwe callout = new VerifyJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "the JWT uses an unacceptable Key Encryption Algorithm.");
  }

  @Test()
  public void decrypt11_ECDH_jwt_alg_mismatch() {

    final String staticJwt =
        "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI1a3M0TUNSb0NNRGRMdVVoSUx2SEdTeFFyYUxmVHlfTWg5bzFNcjlUR2ZrIiwieSI6InhyNmJYVUo2Y0tsbk11ZXVqa2JsTUkzbDV4ZFFlZDVVTTdnMmthUzBJWm8ifSwidHlwIjoiSldUIiwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0.F94FqpWKZzg85V70aJ7FESL_sxZiKF4EdGsYk0MFKZ0gP9-oqMhq_g.rzEAPWo28nhJGI19.kKc0-inKi4NGobU40NgfScCBZEOmaqa8eE6ItEYVUo7lyaxzjTwfqf0y5uqdiX0GSQJfQ4qD7dhe3J2TuJzt4kK6mmNyaxhGCNAibQ.demEL5RiVVQmcdJDCluI8A";

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt11");
    properties.put("private-key", ecPrivateKey1);
    properties.put("key-encryption", "RSA-OAEP-256");
    properties.put("source", "message.content");
    properties.put("max-lifetime", "8m");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", staticJwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "the JWT uses an unacceptable Key Encryption Algorithm.");
  }

  @Test()
  public void decrypt12_ECDH_jwt_success() {

    final String staticJwt =
        "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI1a3M0TUNSb0NNRGRMdVVoSUx2SEdTeFFyYUxmVHlfTWg5bzFNcjlUR2ZrIiwieSI6InhyNmJYVUo2Y0tsbk11ZXVqa2JsTUkzbDV4ZFFlZDVVTTdnMmthUzBJWm8ifSwidHlwIjoiSldUIiwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0.F94FqpWKZzg85V70aJ7FESL_sxZiKF4EdGsYk0MFKZ0gP9-oqMhq_g.rzEAPWo28nhJGI19.kKc0-inKi4NGobU40NgfScCBZEOmaqa8eE6ItEYVUo7lyaxzjTwfqf0y5uqdiX0GSQJfQ4qD7dhe3J2TuJzt4kK6mmNyaxhGCNAibQ.demEL5RiVVQmcdJDCluI8A";

    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "decrypt12");
    properties.put("private-key", ecPrivateKey1);
    properties.put("key-encryption", "ECDH-ES+A256KW");
    properties.put("source", "message.content");
    // properties.put("max-lifetime", "8m");
    properties.put("debug", "true");

    msgCtxt.setVariable("message.content", staticJwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("ejwt", properties);
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    // retrieve output
    String error = msgCtxt.getVariableAsString("ejwt_error");
    Assert.assertNull(error);
    String payload = msgCtxt.getVariableAsString("ejwt_payload");
    Type type = new TypeToken<Map<String, Object>>() {}.getType();
    Map<String, Object> map = new Gson().fromJson(payload, type);
    Assert.assertEquals(map.get("uid"), "D6B455B4-D252-4F4B-82B3-DA908FDB5BD3");
  }
}
