// VerifyEncryptedJwt.java
//
// This is the callout class for the VerifyEncryptedJwt custom policy for Apigee Edge.
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

package com.google.apigee.edgecallouts;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.CalloutUtil;
import com.google.apigee.util.KeyUtil;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@IOIntensive
public abstract class EncryptedJwtBase {
  protected static final String varprefix = "ejwt_";
  private static final Pattern kekNamePattern =
      Pattern.compile("^(RSA-OAEP-256)$", Pattern.CASE_INSENSITIVE);
  private static final Pattern cekNamePattern =
      Pattern.compile(
          "^(A128CBC-HS256|A192CBC-HS384|A256CBC-HS512|A128GCM|A192GCM|A256GCM)$",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern variableReferencePattern =
      Pattern.compile("(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)");
  private static final Pattern commonErrorPattern = Pattern.compile("^(.+?)[:;] (.+)$");

  protected final Map<String, String> properties;

  public EncryptedJwtBase(Map properties) {
    this.properties = CalloutUtil.genericizeMap(properties);
  }

  protected static String varName(String s) {
    return varprefix + s;
  }

  protected String resolveVariableReferences(String spec, MessageContext msgCtxt) {
    if (spec == null || spec.equals("")) return spec;
    Matcher matcher = variableReferencePattern.matcher(spec);
    StringBuffer sb = new StringBuffer();
    while (matcher.find()) {
      matcher.appendReplacement(sb, "");
      sb.append(matcher.group(1));
      String ref = matcher.group(2);
      String[] parts = ref.split(":", 2);
      Object v = msgCtxt.getVariable(parts[0]);
      if (v != null) {
        sb.append((String) v);
      } else if (parts.length > 1) {
        sb.append(parts[1]);
      }
      sb.append(matcher.group(3));
    }
    matcher.appendTail(sb);
    return sb.toString();
  }

  protected String _getStringProp(MessageContext msgCtxt, String name, String defaultValue)
      throws Exception {
    String value = this.properties.get(name);
    if (value != null) value = value.trim();
    if (value == null || value.equals("")) {
      return defaultValue;
    }
    value = resolveVariableReferences(value, msgCtxt);
    if (value == null || value.equals("")) {
      throw new IllegalStateException(name + " resolves to null or empty.");
    }
    return value;
  }

  // private PublicKey getPublicKey(MessageContext msgCtxt) throws Exception {
  //   return KeyUtil.decodePublicKey(_getRequiredString(msgCtxt, "public-key"));
  // }

  protected String _getRequiredString(MessageContext msgCtxt, String name) throws Exception {
    String value = _getStringProp(msgCtxt, name, null);
    if (value == null)
      throw new IllegalStateException(String.format("%s resolves to null or empty.", name));
    return value;
  }

  protected String _getOptionalString(MessageContext msgCtxt, String name) throws Exception {
    return _getStringProp(msgCtxt, name, null);
  }

  protected String getKeyEncryption(MessageContext msgCtxt) throws Exception {
    String alg = _getRequiredString(msgCtxt, "key-encryption");
    alg = resolveVariableReferences(alg.trim(), msgCtxt);
    if (alg == null || alg.equals("")) {
      throw new IllegalStateException("key-encryption resolves to null or empty.");
    }

    Matcher m = kekNamePattern.matcher(alg);
    if (!m.matches()) {
      throw new IllegalStateException("that key-encryption algorithm name is unsupported.");
    }
    return alg;
  }

  protected String getContentEncryption(MessageContext msgCtxt) throws Exception {
    String alg = _getOptionalString(msgCtxt, "content-encryption");
    if (alg != null) alg = alg.trim();
    alg = resolveVariableReferences(alg, msgCtxt);
    if (alg == null || alg.equals("")) {
      return null;
    }
    Matcher m = cekNamePattern.matcher(alg);
    if (!m.matches()) {
      throw new IllegalStateException("that content-encryption algorithm name is unsupported.");
    }
    return alg;
  }

  protected boolean _getBooleanProperty(MessageContext msgCtxt, String propName, boolean defaultValue)
      throws Exception {
    String flag = this.properties.get(propName);
    if (flag != null) flag = flag.trim();
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    flag = resolveVariableReferences(flag, msgCtxt);
    if (flag == null || flag.equals("")) {
      return defaultValue;
    }
    return flag.equalsIgnoreCase("true");
  }

  protected void clearVariables(MessageContext msgCtxt) {
    msgCtxt.removeVariable(varName("error"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  protected void setExceptionVariables(Exception exc1, MessageContext msgCtxt) {
    String error = exc1.toString().replaceAll("\n", " ");
    msgCtxt.setVariable(varName("exception"), error);
    Matcher matcher = commonErrorPattern.matcher(error);
    if (matcher.matches()) {
      msgCtxt.setVariable(varName("error"), matcher.group(2));
    } else {
      msgCtxt.setVariable(varName("error"), error);
    }
  }

}
