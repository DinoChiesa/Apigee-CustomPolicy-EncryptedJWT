// TestDecryptAES.java
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

package com.google.apigee.callouts;

import com.apigee.flow.execution.ExecutionResult;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestDecryptAES extends CalloutTestBase {

  @DataProvider(name = "jwt-decrypt")
  public Object[][] jwtTestCases() {

    return new Object[][] {
      {
        "eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.Rg-1fMLToKobdatSMUk5WPF0JQ8qkBLSx6r_iGbltFRxaPTpjCtdXg.LBi9_gKfmfp8HS8s.94TH0HkYVlEyrSc1DKUlGdtAcOTQf4U5Vll_RrT4OSaYOLLIXm7DMaV16XZ5_gUKqpbXtPVIlAzyrWsYisNityIGG81_0VqPmwOZ-tmyknEsFQ.f3GydBxFnsdyU4hzK574Jg",
        "A256KW",
        "dmeKp87NzllTkXxINuB9JFqXi6kzi9qy",
        null,
        true
      },
      {
        "eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTE5MktXIn0.qNjg5Bvxx2q_wzm-Fl2PxrzQk1HVzam1kmYP1CLTOlMY70TNi_gnZA.dtfBWw_7pvUOx_O8.xCEAF4GmMi--Exq9WJF9V22Tbql72eVSLUzNEMf6x3GfpXjMHBT2v1e7JpWIoUXAMycZY6g1v9aQWAzkGGx5DUn5kl3qXBfBIW6FjNDOSQDfIA.t5oXX0tmKmWA7YyWc2Rn4A",
        "A192KW",
        "WNAVpx07tXubEMpexHqHX07R",
        null,
        true
      },
      {
        "eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiVEdPaTJIOWpMSEduSWY5ZkU0eHFzQSIsImFsZyI6IkExMjhHQ01LVyIsIml2IjoiWVJMRzFsZnZFWjdQdlRKNiJ9.ccvGY_NSGQIYqukTTUTdTJ0_CvDNvpKgcJ9JjqIuDaQ.3OS8iRAN4xKYnwub.AN93tX0aSlx9PNY3hvv9R-TrVMX7AOs2OIvsvYOqrfbrfom32H2Dnafk-B2LmIbwFZnuKpj_4gKTz3Pu15MJaFdZhHmGh8pA2im8Orcoq_xNRQ.blkYkyuTmrZss-6xLmsbOw",
        "A128GCMKW",
        "c94oSxGey2avD0GE",
        null,
        true
      },
      {
        "eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiVEdPaTJIOWpMSEduSWY5ZkU0eHFzQSIsImFsZyI6IkExMjhHQ01LVyIsIml2IjoiWVJMRzFsZnZFWjdQdlRKNiJ9.cdvGY_NSGQIYqukTTUTdTJ0_CvDNvpKgcJ9JjqIuDaQ.3OS8iRAN4xKYnwub.AN93tX0aSlx9PNY3hvv9R-TrVMX7AOs2OIvsvYOqrfbrfom32H2Dnafk-B2LmIbwFZnuKpj_4gKTz3Pu15MJaFdZhHmGh8pA2im8Orcoq_xNRQ.blkYkyuTmrZss-6xLmsbOw",
        "A128GCMKW",
        "c94oSxGey2avD0GE",
        null,
        false // modified JWT
      },
      {
        "eyJ0eXAiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTE5MktXIn0.qNjg5Bvxx2q_wzm-Fl2PxrzQk1HVzam1kmYP1CLTOlMY70TNi_gnZA.dtfBWw_7pvUOx_O8.xCEAF4GmMi--Exq9WJF9V22Tbql72eVSLUzNEMf6x3GfpXjMHBT2v1e7JpWIoUXAMycZY6g1v9aQWAzkGGx5DUn5kl3qXBfBIW6FjNDOSQDfIA.t5oXX0tmKmWA7YyWc2Rn4A",
        "A192KW",
        "dmeKp87NzllTkXxINuB9JFqXi6kzi9qy", // incorrect key
        null,
        false
      },
    };
  }

  @DataProvider(name = "jwe-decrypt")
  public Object[][] jweTestCases() {

    return new Object[][] {
      {
        "eyJwMSI6IjdBbTVaSWgiLCJjdHkiOiJ0eHQiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiaUNGS0JKTzljb2NBWnU0M2U0OXpHZyIsImFsZyI6IkExMjhHQ01LVyIsIml2Ijoia3htM2ZCbVpXOWVJQ0JoZCJ9.dKsjpCHrlXaOLEqdejsCSkNoZtubEZoZMpj_sGJHXPk.btztshIelKThHGWL.tALm87QMeKr1FPEzGiSVQkNVh7XFa9wkxD7cOBaylZv23e3KS_c1BwuFNrqUGascQ0cs28JH7HCJqn2S9P-sAFlRqUehP7RtyX0SSAuaKua2PcerC-9IJrlwCnQjvtFj4cCAHrqBa9RHdpbbxs16xpVB-o8F2LKUAwwMxLkojsuhw0ZJyfaUXtqXg-gdfSK5GOdShKhUsU7TUuPYGY3I7haJGesoJWsVMw1LhaUEIuzLElXN6DdVVjr4EStuyxnUL2OvzwBg-w3rYcfVOUmlX7UDUiyiEQxvikzuL1BMXiEDe4tIxA5PzJ9nNh7KzM2MSnWhos-EY-Z4x8433qeUa1A5OdwoBCBZFEwtJlmjbaPYQbD9uiwMmb1al4g-LryCtW30J9Z5Kf7P6A4KqogeyF94bRxddTGUQTssEqOIb7U2sPuKVWJn3YUx5PJAppsslnkERt7IXvkH7sfqCbiUSUyb8b_xvDVz1I-ZIQlZ19kNRgA7fR1b0Wlem-okAk52d3rpKZyU7NueRpD_VBnyHmaeidmpBwJW3jNvcd5jqRi-cvyyZKfTHT0c-cIIKpumVs820QBZyRBvITN1rDDi3dGvFS81OJlYf8w32QZb4xZg4XJzjQTHOF5zlaWoV8wKqU1Fll_4BJdbP501RTzAGfvNjpegoMGlrk5MtPBzld1E_OdZP-y-9Ew4v7kCrHkeRMCHKVSS45d86pvwqjqO7c0omOtJxywv7plULAxtnNUt2ZBxh8OQx5u2h550wHTmzy8cNbUqH6YsBvxqIhF4yVWH2kwDxfy3nrlY9XM.EIoQRdUCy-stKVsGTq-qkg",
        "A128GCMKW",
        "iasLYflPXQPh74dY",
        null,
        true
      },
      {
        "eyJwMSI6IjdBbTVaSWgiLCJjdHkiOiJ0eHQiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiaUNGS0JKTzljb2NBWnU0M2U0OXpHZyIsImFsZyI6IkExMjhHQ01LVyIsIml2Ijoia3htM2ZCbVpXOWVJQ0JoZCJ9.dKsjpCHrlXaOLEqdejsCSkNoZtubEZoZMpj_sGJHXPk.btztshIelKThHGWL.tALm87QMeKr1FPEzGiSVQkNVh7XFa9wkxD7cOBaylZv23e3KS_c1BwuFNrqUGascQ0cs28JH7HCJqn2S9P-sAFlRqUehP7RtyX0SSAuaKua2PcerC-9IJrlwCnQjvtFj4cCAHrqBa9RHdpbbxs16xpVB-o8F2LKUAwwMxLkojsuhw0ZJyfaUXtqXg-gdfSK5GOdShKhUsU7TUuPYGY3I7haJGesoJWsVMw1LhaUEIuzLElXN6DdVVjr4EStuyxnUL2OvzwBg-w3rYcfVOUmlX7UDUiyiEQxvikzuL1BMXiEDe4tIxA5PzJ9nNh7KzM2MSnWhos-EY-Z4x8433qeUa1A5OdwoBCBZFEwtJlmjbaPYQbD9uiwMmb1al4g-LryCtW30J9Z5Kf7P6A4KqogeyF94bRxddTGUQTssEqOIb7U2sPuKVWJn3YUx5PJAppsslnkERt7IXvkH7sfqCbiUSUyb8b_xvDVz1I-ZIQlZ19kNRgA7fR1b0Wlem-okAk52d3rpKZyU7NueRpD_VBnyHmaeidmpBwJW3jNvcd5jqRi-cvyyZKfTHT0c-cIIKpumVs820QBZyRBvITN1rDDi3dGvFS81OJlYf8w32QZb4xZg4XJzjQTHOF5zlaWoV8wKqU1Fll_4BJdbP501RTzAGfvNjpegoMGlrk5MtPBzld1E_OdZP-y-9Ew4v7kCrHkeRMCHKVSS45d86pvwqjqO7c0omOtJxywv7plULAxtnNUt2ZBxh8OQx5u2h550wHTmzy8cNbUqH6YsBvxqIhF4yVWH2kwDxfy3nrlY9XM.EIoQRdUCy-stKVsGTq-qkg",
        "A128GCMKW",
        "iasLYflPXQPh74AY", // wrong key
        null,
        false
      },
      {
        "eyJwMSI6IjdBbTVaSWgiLCJjdHkiOiJ0eHQiLCJlbmMiOiJBMjU2R0NNIiwidGFnIjoiaUNGS0JKTzljb2NBWnU0M2U0OXpHZyIsImFsZyI6IkExMjhHQ01LVyIsIml2Ijoia3htM2ZCbVpXOWVJQ0JoZCJ9.dKsjpCHrlXaOLEqdejsCSkNoZtubEZoZMpj_sGJHXPk.btztshIelKThHGWL.tALm87QMeKr1FPEzGiSVQkNVh7XFa9wkxD7cOBaylZv23e3KS_c1BwuFNrqUGascQ0cs28JH7HCJqn2S9P-sAFlRqUehP7RtyX0SSAuaKua2PcerC-9IJrlwCnQjvtFj4cCAHrqBa9RHdpbbxs16xpVB-o8F2LKUAwwMxLkojsuhw0ZJyfaUXtqXg-gdfSK5GOdShKhUsU7TUuPYGY3I7haJGesoJWsVMw1LhaUEIuzLElXN6DdVVjr4EStuyxnUL2OvzwBg-w3rYcfVOUmlX7UDUiyiEQxvikzuL1BMXiEDe4tIxA5PzJ9nNh7KzM2MSnWhos-EY-Z4x8433qeUa1A5OdwoBCBZFEwtJlmjbaPYQbD9uiwMmb1al4g-LryCtW30J9Z5Kf7P6A4KqogeyF94bRxddTGUQTssEqOIb7U2sPuKVWJn3YUx5PJAppsslnkERt7IXvkH7sfqCbiUSUyb8b_xvDVz1I-ZIQlZ19kNRgA7fR1b0Wlem-okAk52d3rpKZyU7NueRpD_VBnyHmaeidmpBwJW3jNvcd5jqRi-cvyyZKfTHT0c-cIIKpumVs820QBZyRBvITN1rDDi3dGvFS81OJlYf8w32QZb4xZg4XJzjQTHOF5zlaWoV8wKqU1Fll_4BJdbP501RTzAGfvNjpegoMGlrk5MtPBzld1E_OdZP-y-9Ew4v7kCrHkeRMCHKVSS45d86pvwqjqO7c0omOtJxywv7plULAxtnNUt2ZBxh8OQx5u2h550wHTmzy8cNbUqH6YsBvxqIhF4yVWH2kwDxfy3nrlY9XM.EIoQRdUCy-stKVsGTq-qkg",
        "A128KW", // wrong alg
        "iasLYflPXQPh74dY",
        null,
        false
      },
    };
  }

  @Test(dataProvider = "jwt-decrypt")
  public void JWT_Decrypt(
      String jwt, String alg, String encodedKey, String keyEncoding, Boolean successExpected) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWT_Decrypt");
    properties.put("key-encryption", alg);
    properties.put("secret-key", encodedKey);
    properties.put("secret-key-encoding", keyEncoding);
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwt);

    VerifyEncryptedJwt callout = new VerifyEncryptedJwt(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);
    String error = msgCtxt.getVariableAsString("ejwt_error");

    // check result and output
    reportThings("ejwt", properties);
    if (successExpected) {
      Assert.assertEquals(result, ExecutionResult.SUCCESS);
      Assert.assertNull(error);
    } else {
      Assert.assertEquals(result, ExecutionResult.ABORT);
      Assert.assertNotNull(error);
    }
  }

  @Test(dataProvider = "jwe-decrypt")
  public void JWE_Decrypt(
      String jwe, String alg, String encodedKey, String keyEncoding, Boolean successExpected) {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put("testname", "JWT_Decrypt");
    properties.put("key-encryption", alg);
    properties.put("secret-key", encodedKey);
    properties.put("secret-key-encoding", keyEncoding);
    properties.put("debug", "true");
    properties.put("source", "message.content");

    msgCtxt.setVariable("message.content", jwe);

    VerifyJwe callout = new VerifyJwe(properties);
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
}
