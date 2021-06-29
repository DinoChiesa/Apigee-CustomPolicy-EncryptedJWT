// EncryptedJoseBase.java
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
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.CalloutUtil;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@IOIntensive
public abstract class EncryptedJoseBase {
  private static final Pattern kekNamePattern =
      Pattern.compile("^(RSA-OAEP-256|RSA-OAEP)$", Pattern.CASE_INSENSITIVE);
  private static final Pattern cekNamePattern =
      Pattern.compile(
          "^(A128CBC-HS256|A192CBC-HS384|A256CBC-HS512|A128GCM|A192GCM|A256GCM)$",
          Pattern.CASE_INSENSITIVE);

  private static final Pattern variableReferencePattern =
      Pattern.compile("(.*?)\\{([^\\{\\} :][^\\{\\} ]*?)\\}(.*?)");
  private static final Pattern commonErrorPattern = Pattern.compile("^(.+?)[:;] (.+)$");

  abstract String getVarPrefix();

  protected final Map<String, String> properties;

  public EncryptedJoseBase(Map properties) {
    this.properties = CalloutUtil.genericizeMap(properties);
  }

  protected String varName(String s) {
    return getVarPrefix() + s;
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
        sb.append(v.toString());
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

  protected boolean _getBooleanProperty(
      MessageContext msgCtxt, String propName, boolean defaultValue) throws Exception {
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
    msgCtxt.removeVariable(varName("output"));
    msgCtxt.removeVariable(varName("exception"));
    msgCtxt.removeVariable(varName("stacktrace"));
    msgCtxt.removeVariable(varName("alg"));
    msgCtxt.removeVariable(varName("enc"));
    msgCtxt.removeVariable(varName("header"));
    msgCtxt.removeVariable(varName("payload"));
    msgCtxt.removeVariable(varName("age"));
  }

  protected static String getStackTraceAsString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return sw.toString();
  }

  protected void setVariables(
      Map<String, Object> payloadClaims, Map<String, Object> headerClaims, MessageContext msgCtxt)
      throws Exception {
    if (payloadClaims != null) {
      payloadClaims.forEach(
          (key, value) -> msgCtxt.setVariable(varName("payload_" + key), value.toString()));
    }
    headerClaims.forEach(
        (key, value) -> msgCtxt.setVariable(varName("header_" + key), value.toString()));
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
