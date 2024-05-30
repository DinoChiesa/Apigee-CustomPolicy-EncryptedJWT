// CalloutUtil.java
//
// This is a utility class for custom policies in Apigee.
// For full details see the Readme accompanying this source file.
//
// Copyright (c) 2018-2024 Google LLC
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

package com.google.apigee.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public final class CalloutUtil {

  public static Map<String, String> genericizeMap(Map properties) {
    // convert an untyped Map to a generic map
    Map<String, String> m = new HashMap<String, String>();
    Iterator iterator = properties.keySet().iterator();
    while (iterator.hasNext()) {
      Object key = iterator.next();
      Object value = properties.get(key);
      if ((key instanceof String) && (value instanceof String)) {
        m.put((String) key, (String) value);
      }
    }
    return Collections.unmodifiableMap(m);
  }
}
