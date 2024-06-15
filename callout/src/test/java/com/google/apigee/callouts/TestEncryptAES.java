// TestEncryptAES.java
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
import com.google.apigee.encoding.Base16;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestEncryptAES extends CalloutTestBase {

  public static int generateRandom(int start, int end) {
    Random rand = new Random();
    int range = end - start + 1;
    return rand.nextInt(range - 1) + start;
  }

  public static int generateRandomWithExclusion(int start, int end, Integer[] excluded) {
    final int randomNum = generateRandom(start, end);
    boolean isExcluded = Arrays.stream(excluded).anyMatch(x -> x == randomNum);
    final int delta = (isExcluded) ? (end == randomNum ? -1 : 1) : 0;
    return randomNum + delta;
  }

  static Function<String, Object[]> toObjArray = fname -> new Object[] {fname};

  static Object[][] to2Darray(String[] a) {
    return Arrays.stream(a).map(toObjArray).toArray(Object[][]::new);
  }

  @DataProvider(name = "128bit-keys")
  public static Object[][] getDataFor128BitCases() {
    return to2Darray(new String[] {"A128KW", "A128GCMKW"});
  }

  @DataProvider(name = "192bit-keys")
  public static Object[][] getDataFor192BitCases() {
    return to2Darray(new String[] {"A192KW", "A192GCMKW"});
  }

  @DataProvider(name = "256bit-keys")
  public static Object[][] getDataFor256BitCases() {
    return to2Darray(new String[] {"A256KW", "A256GCMKW"});
  }

  @DataProvider(name = "mismatched-alg-and-keylength")
  public Object[][] mismatchedAlgData() {
    final String fixedKeyValues =
        "The Key Encryption Key length must be 128 bits \\(16 bytes\\), 192 bits \\(24 bytes\\) or"
            + " 256 bits \\(32 bytes\\)";

    final String notSupported =
        "The \"[A][^\"]+KW\" algorithm is not supported by the JWE encrypter: Supported algorithms:"
            + " \\[.+\\]";

    return new Object[][] {
      // Using a key length that is not one of {16,24,32} results in a specific error.

      {
        "A128KW",
        (Integer) generateRandomWithExclusion(5, 32, new Integer[] {16, 24, 32}),
        fixedKeyValues
      },
      {
        "A192KW",
        (Integer) generateRandomWithExclusion(5, 32, new Integer[] {16, 24, 32}),
        fixedKeyValues
      },
      {
        "A256KW",
        (Integer) generateRandomWithExclusion(5, 32, new Integer[] {16, 24, 32}),
        fixedKeyValues
      },
      {
        "A128GCMKW",
        (Integer) generateRandomWithExclusion(5, 32, new Integer[] {16, 24, 32}),
        fixedKeyValues
      },
      {
        "A192GCMKW",
        (Integer) generateRandomWithExclusion(5, 32, new Integer[] {16, 24, 32}),
        fixedKeyValues
      },
      {
        "A256GCMKW",
        (Integer) generateRandomWithExclusion(5, 32, new Integer[] {16, 24, 32}),
        fixedKeyValues
      },

      // using a mismatched key length gives a different error
      {"A256GCMKW", (Integer) 16, notSupported},
      {"A256GCMKW", (Integer) 24, notSupported},
      {"A256KW", (Integer) 16, notSupported},
      {"A256KW", (Integer) 24, notSupported},
      {"A128GCMKW", (Integer) 32, notSupported},
      {"A128GCMKW", (Integer) 24, notSupported},
      {"A128KW", (Integer) 32, notSupported},
      {"A128KW", (Integer) 24, notSupported},
      {"A192GCMKW", (Integer) 32, notSupported},
      {"A192GCMKW", (Integer) 16, notSupported},
      {"A192KW", (Integer) 32, notSupported},
      {"A192KW", (Integer) 16, notSupported},
    };
  }

  @DataProvider(name = "key-encoding")
  public Object[][] keyEncodingData() {

    return new Object[][] {
      {"A128KW", "0123456789ABCDEF", null, true},
      {"A128KW", "0123456789ABCDEF", "utf-8", true},
      {"A128KW", "MDEyMzQ1Njc4OUFCQ0RFRg", "base64", true},
      {"A128KW", "0123456789ABCDEF", "base64", false},
      {"A128KW", "0a0b0c0d0e0f00010203040506070809", "base16", true},
      {"A128KW", "0a0b0c0d0e0f000102030405060708", "base16", false},
      {"A128KW", "this-wont-decode", "base16", false},
      {"A256KW", "0123456789ABCDEF0123456789ABCDEF", null, true},
      {"A256KW", "0123456789ABCDEF0123456789ABCDEF", "utf-8", true},
      {"A256KW", "0123456789ABCDEF0123456789ABCDEF", "base64", false},
      {"A256KW", "MDEyMzQ1Njc4OUFCQ0RFRi1UaGlzLWlzLXNlY3JldCE", "base64", true},
    };
  }

  @Test(dataProvider = "128bit-keys")
  public void JWT_128(String alg) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWT_128_" + alg);
    properties.put("secret-key", "{random-key}");
    properties.put("key-encryption", alg);
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload",
        "{ \"sub\": \"dino\", \"something\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");
    msgCtxt.setVariable("random-key", StringGen.randomString(16));

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

  @Test(dataProvider = "192bit-keys")
  public void JWT_192(String alg) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWT_192_" + alg);
    properties.put("secret-key", "{random-key}");
    properties.put("key-encryption", alg);
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload",
        "{ \"sub\": \"dino\", \"something\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");
    msgCtxt.setVariable("random-key", StringGen.randomString(24));

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

  @Test(dataProvider = "256bit-keys")
  public void JWT_256_(String alg) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWT_256_" + alg);
    properties.put("secret-key", "{random-key}");
    properties.put("key-encryption", "A256KW");
    properties.put("content-encryption", "A256GCM");
    properties.put(
        "payload",
        "{ \"sub\": \"dino\", \"something\" : \"D6B455B4-D252-4F4B-82B3-DA908FDB5BD3\"}");
    properties.put("debug", "true");
    msgCtxt.setVariable("random-key", StringGen.randomString(32));

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

  @Test(dataProvider = "128bit-keys")
  public void JWE_128(String alg) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWE_128_" + alg);
    properties.put("secret-key", "{random1}");
    properties.put("key-encryption", alg);
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", gettysburg);
    properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"txt\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(16));
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

  @Test(dataProvider = "192bit-keys")
  public void JWE_192(String alg) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWE_192_" + alg);
    properties.put("secret-key", "{random1}");
    properties.put("key-encryption", alg);
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(24));
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

  @Test(dataProvider = "256bit-keys")
  public void JWE_256(String alg) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWE_256_" + alg);
    properties.put("secret-key", "{random1}");
    properties.put("key-encryption", alg);
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(32));
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

  @Test(dataProvider = "mismatched-alg-and-keylength")
  public void JWE_wrong_key_length(String alg, Integer keylength, String expectedErrorRegex) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWE_wrong_key_length_" + alg);
    properties.put("secret-key", "{random1}");
    properties.put("key-encryption", alg);
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(keylength));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    System.out.printf("comparing (%s) to\n          (%s)...\n", error, expectedErrorRegex);
    Assert.assertTrue(error.matches(expectedErrorRegex));

    String output = msgCtxt.getVariableAsString("jwe_output");
    Assert.assertNull(output);
  }

  @Test
  public void JWE_256_key_too_long() {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWE_256_key_too_long");
    properties.put("secret-key", "{random1}");
    properties.put("key-encryption", "A256KW");
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random1", StringGen.randomString(37));
    msgCtxt.setVariable("random2", StringGen.randomString(7));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    reportThings("jwe", properties);
    Assert.assertEquals(result, ExecutionResult.ABORT);
    // retrieve output
    String error = msgCtxt.getVariableAsString("jwe_error");
    Assert.assertNotNull(error);
    Assert.assertEquals(error, "that key is too long.");
  }

  @Test(dataProvider = "key-encoding")
  public void JWE_encoded_key(
      String alg, String encodedKey, String keyEncoding, Boolean successExpected) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWE_encoded_key");
    properties.put("key-encryption", alg);
    properties.put("secret-key", encodedKey);
    properties.put("secret-key-encoding", keyEncoding);
    properties.put("content-encryption", "A256GCM");
    properties.put("payload", jwt1);
    properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
    properties.put("debug", "true");

    msgCtxt.setVariable("random2", StringGen.randomString(17));

    GenerateJwe callout = new GenerateJwe(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String error = msgCtxt.getVariableAsString("jwe_error");

    // check result and output
    reportThings("jwe", properties);

    if (successExpected) {
      Assert.assertEquals(result, ExecutionResult.SUCCESS);
      Assert.assertNull(error);
    } else {
      Assert.assertEquals(result, ExecutionResult.ABORT);
      Assert.assertNotNull(error);
    }
  }

  @Test
  public void JWE_random_256bit_base64_encoded_key() {

    for (int i = 0; i < 100; i++) {
      byte[] b = new byte[32];
      new Random().nextBytes(b);

      String encoded_256bit_key = Base64.getUrlEncoder().encodeToString(b);

      Map<String, String> properties = new HashMap<String, String>();
      properties.put("testname", "JWE_encoded_key");
      properties.put("key-encryption", "A256KW");
      properties.put("secret-key", encoded_256bit_key);
      properties.put("secret-key-encoding", "base64url");
      properties.put("content-encryption", "A256GCM");
      properties.put("payload", jwt1);
      properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
      properties.put("debug", "true");

      msgCtxt.setVariable("random2", StringGen.randomString(17));

      GenerateJwe callout = new GenerateJwe(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
      String error = msgCtxt.getVariableAsString("jwe_error");

      // check result and output
      reportThings("jwe", properties);

      Assert.assertEquals(result, ExecutionResult.SUCCESS);
      Assert.assertNull(error);
    }
  }

  @Test
  public void JWE_random_256bit_base16_encoded_key() {
    for (int i = 0; i < 100; i++) {
      byte[] b = new byte[32];
      new Random().nextBytes(b);

      String encoded_256bit_key = Base16.encode(b);

      Map<String, String> properties = new HashMap<String, String>();
      properties.put("testname", "JWE_encoded_key");
      properties.put("key-encryption", "A256KW");
      properties.put("secret-key", encoded_256bit_key);
      properties.put("secret-key-encoding", "base16");
      properties.put("content-encryption", "A256GCM");
      properties.put("payload", jwt1);
      properties.put("header", "{ \"p1\": \"{random2}\", \"cty\": \"JWT\"}");
      properties.put("debug", "true");

      msgCtxt.setVariable("random2", StringGen.randomString(17));

      GenerateJwe callout = new GenerateJwe(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
      String error = msgCtxt.getVariableAsString("jwe_error");

      // check result and output
      reportThings("jwe", properties);

      Assert.assertEquals(result, ExecutionResult.SUCCESS);
      Assert.assertNull(error);
    }
  }
}
