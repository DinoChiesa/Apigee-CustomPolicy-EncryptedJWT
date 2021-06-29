// TimeResolverTest.java
//
// Test code for the TimeResolver.
//
// Copyright (c) 2021 Google LLC
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

import java.util.function.BiConsumer;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TimeResolverTest {

  @Test()
  public void resolveExpressions() {
    BiConsumer<Long, Long> equal = (actual, expected) -> Assert.assertEquals(actual, expected);

    equal.accept(TimeResolver.resolveExpression("10s"), 10 * 1000L);
    equal.accept(TimeResolver.resolveExpression("10m"), 10 * 60 * 1000L);
    equal.accept(TimeResolver.resolveExpression("7h"), 7 * 60 * 60 * 1000L);
    equal.accept(TimeResolver.resolveExpression("3d"), 3 * 24 * 60 * 60 * 1000L);
    equal.accept(TimeResolver.resolveExpression("5w"), 5 * 7 * 24 * 60 * 60 * 1000L);
    equal.accept(TimeResolver.resolveExpression("20"), 20 * 1000L);
    equal.accept(TimeResolver.resolveExpression("-1"), -1000L);
    equal.accept(TimeResolver.resolveExpression("ksj0lx"), 0L);
    equal.accept(TimeResolver.resolveExpression("-10m"), -10 * 60 * 1000L);
  }
}
