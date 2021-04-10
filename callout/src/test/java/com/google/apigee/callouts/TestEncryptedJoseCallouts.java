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

public class TestEncryptedJoseCallouts {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  MessageContext msgCtxt;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map<String, Object> variables;

          public void $init() {
            getVariables();
          }

          private Map<String, Object> getVariables() {
            if (variables == null) {
              variables = new HashMap<String, Object>();
            }
            return variables;
          }

          @Mock()
          public Object getVariable(final String name) {
            return getVariables().get(name);
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            System.out.printf("set(%s) = %s\n", name, value.toString());
            getVariables().put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (getVariables().containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
    System.out.printf("=============================================\n");
  }

  private String privateKey1 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXk9k01JrhGQf1\n"
          + "4B4nymHntaG9SYA2kEQOo/RK4fM2XcebFsSJQ8GgE1AC1GlWU5YzS34WW0w5GMZe\n"
          + "2e2NIGz/x2jeRo9so3hRrQ7/BGl7XnAedEE1P5XmqidQPLRH6B8GoGkw1UifZvXH\n"
          + "kRaKHXSwwJT6uOdS8Fi0IYeZtCVRxk5ltctJZ9Xe6ShFoYbYpX1XbM1daNNmIpIV\n"
          + "EUllJ5bixP6z23BybH5AXrTGSmp7j8O+upqcpvdsoZChWILTCXru/O/5B9ou2S79\n"
          + "YCwF4uYjcMWZdvSfLe4JQJ8JG0eekBTSB+NYGLCRn9HY6Fk5bzvsYZw0wpVOcVPr\n"
          + "3XWAYyJLAgMBAAECggEAPA3692W207hWaF+L5wfRKGyH5yRfrFOaMf3ooye4yk9r\n"
          + "uL+p9pdCjGZ05qTnx123vQht0qqSXGGTeX76V1NOKh8SDsHXWKtdbFtqjw5amDyh\n"
          + "vUojlELnbn++PfL7QgDfC8iKJUl1VrqnA3ZeshEsncS4e/QgtRExlNS2YtI1h0bU\n"
          + "8xaz45QmARgwI/g25gO8hP9iBABk3iNBY96+Kr65ReY8Ivof6Y2yha0ZPEwEfehQ\n"
          + "UxCULh6RDSnUoeOvTu7vxyfb1729PU/0kTr0rRdXIwdvIRqimlLjfm+697dsFvSh\n"
          + "eRK6pKp0GTzxwhkUKck3vAtsRlD+fZIxM2ezMAsg8QKBgQD9WwQL83gE61zDHvvQ\n"
          + "S9LiXmSJGmS9z3KqC5bfVXlCPumf1qWLzZnwa0L6k1wamTVcmOV8zt6uh+Re7dAf\n"
          + "SUz1H8obBpFoemk+v0HDUd4q8Aiqp8wP5rHKYSJbeFIWQPQ/yhZwM3v5iyEN36/X\n"
          + "w+gPHyzRRudbAB9KfzUTyziKeQKBgQDZ0+Ma8AYzgjvZbvCbRiglbg+55rBx38Sm\n"
          + "zgl3Z0OYQnBXCW6rewc/aoSrW6zjZZoaCQ+HWg/rvCk1aDO4mdgi1zXRi531XvE5\n"
          + "IGKAUMxmz6VhFrBhUiU0kA2kZTbKqcCQV2AEcpntiIVQWOxcyxzzbw9nz6YvZyTV\n"
          + "QRCOlOzh4wKBgQCB61Vk54IJS8RyzoWk5+0JZgw5/k3gw+tx5aWFeyhGX0qgS4ry\n"
          + "6Qjir65WHpDhluU1SbaMzOyGJWtnfp32HTmYjaevOiwAnp0vrxYDGg1KiXJ4SLmt\n"
          + "Acj0FeFvdIDrpn1Z5MCi4tPVQJI/shBTHcP3VS4/VxO2p5ZkNl06fEDPSQKBgFqX\n"
          + "fMQfPvT9HNb5BKgPLXMjqvatsoQphCe7WMSH9dzFBOOt0JEQwZrmOfbqUaThBI3/\n"
          + "Zq3sDuMDhj/n7lq/4NvclU1ou3Do43nWtiCXeeroQOd4ADL5bu/FWWcdkQQIRUXC\n"
          + "kPRIlSvss0UPNn4BGzFC5y1NdtgQFYl7Xd9uoHXxAoGATpP/SIufCM3mVCoosSan\n"
          + "ylM0iYCqW+KUhECYlqSqvo7JIfv5tv8qejSi03QS1WHHp8OMqqSfCLEE3tTmcSP1\n"
          + "hHYu+QiRZnABbpD9C1+Akh4dG97Woyfd5igBsT1Ovs9PDCN0rO4I2nJHrNLJSPte\n"
          + "OtpRWoF2/LERvp6RNeXthgs=\n"
          + "-----END PRIVATE KEY-----\n";

  private String privateKey2 =
      "-----BEGIN RSA PRIVATE KEY-----\n"
          + "MIIEowIBAAKCAQEArouIADal6Q1l3I5RfBaNLtvb826+Djm4UrfI5jpO54K6j3Gs\n"
          + "vCRMYpz++SQ45sP31gFpl3jvBVyQ83DlUTWsyb1zpjftLLHK04NJeFawS1Nbtj+2\n"
          + "V56t7Zbl1byLbr8Rw1c8IO04oqnycrcAU33KEdF5vluCvg8qpVCJz+AV1ZVNLWiL\n"
          + "flyCVsF1RYlS/OfXVxeKQTE6k3UPDkg/5UOhZYZ1W96KyJwNM4lrziGqBWJIl6da\n"
          + "YsJuT34Z4iOTVsDHPE9yeXFsaftdaPLe0augk6B/5we1CbQeijhPUmcnzmf6ArAG\n"
          + "mtwooPLjowFjwOv1HS7sG67ODvzZY791hcbExQIDAQABAoIBACmoz+sNIAhB1GAR\n"
          + "78zoLQZUH2k4s0/94sqLZv3cSNzkzNZT0WCOYVTgF9MrHBGoEE0ZxTQL/zCOaWJR\n"
          + "PcpmPzlfaGzxyD/0p25YVX7NYgJ4gNk8166OBwFAFNcwyy7Bl+HBvm41cGESovVS\n"
          + "TFehHEuobaBLgycNw6X1VQ8ycsOpG+UbRTJ/QV0KU/OW+CrEHGvaGxLy0ycxjjoC\n"
          + "feHW17+Us2qeBvNXOaxPHeoLg9+0wln2WuoHOHRKD+JJWhOCK9rQYK0BwjnRmYyI\n"
          + "czOPTL1aOkIwb+u2t9kesoA5E4znlPhOKQj+niqHhTNoRAJdSZwZrBYfFvZ4FueM\n"
          + "8sAnGvkCgYEA3Jucwoxrt5JaZUP/Zjbiby9mnYK2B7+vl7BVk3hkCKbuQIGnbn6G\n"
          + "ZJV6EIMUWLkb8+nloeSvy7+1AkWxXY7VYwuzqvWqhrmoXjBygHr6KtrLsz7Ogmij\n"
          + "EZrsZCK3/3DWJgylZOv5PB1rj8V6L7QePmj83gI4/FYJprPVJJnQaPMCgYEAyowd\n"
          + "QDnH4PzWmSfzlso00RAde6LsF0Qpq2so+nQxkLfYJjMPYWXWuvznz+6wyNEPRiI9\n"
          + "XomgB/EfiR8PlNq8j85Xksr+2XQqOQYgVgZC8040vpNLybgqS1uqIPNVJbbpGDXA\n"
          + "w+9f+a+oMgE/dqZtnKBOVTKUVz6+JigUC4LUCWcCgYEArsmoYUhKjC6r6nH+qCiy\n"
          + "LW+7+O44dVk9sYynsOkBMQ251WgklVov9v+rr+t7MnSvngjixOthEai5rKw1RDBI\n"
          + "B2qdFsYALzBoIwB1qDBHh67FGCaaDh8DnI5H32rWp8/qDEmWvahtV2Dj+Qx4q9Uk\n"
          + "5UPfnbLbHaq5iNgQ9yfbRVsCgYAulAAaB++WJq6288AJmiCBP0J4byP5ybwHZpI6\n"
          + "3kOTsyNqzW0pCcFSqNwqLgrLc4AesbsJJX7+tI16/ACaS573Nw1efX4Txan8CROg\n"
          + "lLoKt55bgQX5sndPcxnxj+Ox05lQ7vOQW1jn02RLc4wDngww65B3+TSxx4T0w1yw\n"
          + "tPpL2wKBgAkX/+M6w38bKZ740Kf8Hu8qoUtpu/icf3zkqtjHGQyIxWgq+vDenJJM\n"
          + "GZev6o3c0OtTndUYwFIrxzZaL1gP6Tb8QGuIA49VVMEvWXJl/rPaa5Ip17ee0YnX\n"
          + "BhkCjT+pD2dW1X9S9C6IgcTF8f6Ta27omyw3aqpxefpiVVSbV/I9\n"
          + "-----END RSA PRIVATE KEY-----\n";

  private String publicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA15PZNNSa4RkH9eAeJ8ph\n"
          + "57WhvUmANpBEDqP0SuHzNl3HmxbEiUPBoBNQAtRpVlOWM0t+FltMORjGXtntjSBs\n"
          + "/8do3kaPbKN4Ua0O/wRpe15wHnRBNT+V5qonUDy0R+gfBqBpMNVIn2b1x5EWih10\n"
          + "sMCU+rjnUvBYtCGHmbQlUcZOZbXLSWfV3ukoRaGG2KV9V2zNXWjTZiKSFRFJZSeW\n"
          + "4sT+s9twcmx+QF60xkpqe4/DvrqanKb3bKGQoViC0wl67vzv+QfaLtku/WAsBeLm\n"
          + "I3DFmXb0ny3uCUCfCRtHnpAU0gfjWBiwkZ/R2OhZOW877GGcNMKVTnFT6911gGMi\n"
          + "SwIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  private static final String jwt1 =
      "eyJ0eXAiOiJKV1QiLCJoZHIxIjoxMjMsImVuYyI6IkExMjhHQ00iLCJoZHIyIjp0cnVlLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.n3CicDJeNIdfRHuS9XBAvP1Sep2eyiEIPgvodY4BxzUfUEKxPnWvPVSx-ikaxan5Oi_PSqipIdnPSBJ7pNN1Rt4aqFEBBW5m0WCUwsssyLP0A_MD8usUVg0VqRqBFXqokbTIEO7YCXxGP-bXs-I_1eeuqN12-OokkcWJtyf-n8-HHpp-DAc8xQkYB5oQZqC5rGGAWJh0tThSkynepvJzymaXETiO69B6vU6Oe2VL2PWgMYoB3YjfdEKSZelFe7dLd14G_G5sDKkA33vHjC3w9OPAHlubYpZnWuBdrLH9sV-YSkyLRtiWc-rG1eHIFODcbUXqiDBrhPSfWJlf6wd1_Q.mRqogt0pxtPdgyjt.73XlhsvhcsaIFJUrqZFyf0Hjgxx9A-rbPWoIdsup-ScsXuqO6RevhNdjBg.ESdhCa_eqd2FaI5e5IH2xQ";

  private static final String jwt2 =
      "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.vqVKvZcGr7b7MWzSCmYUVXolSTXW-eCzN_ly03gzix47HBYkk7-nQ_kocdeLOr_qV3pTusJedfq6RyeSsccCu0aJionCureBxtn9udM2MZ1OCNmGIBJhWxDqAKIYOmB_IwTK6ATGRRiqOssw1y1x4PWH13QT_Jxf0VuWDZXm74Cz_ttL_dmtZp7zIM47imjUxRhOCdLdBtYkT2Q-9r__WHq1XOVuYiuLaMBnJ3YPtONhwHbyAJ1TshDgkffllivRs9qs7ONy6fvc9OlYkEoUs2zYGAupMUX1YHSnS62ASnEUMcq9lJsxK32Rvh-DmchgtTMvOH1hBoFnuzzi6p3crg.BRTKgJtcL3mLplCd.8lu-rdSOiH_Qvt0KOM6MxuYkf096ldFGuOiCJigzJxQWMyY4UTNkkkl_FFK4bO76w46c5Ub66l3AXWxT9OwwX4A3KwaDI9USEfRUBuXW3S7fSmVrjEu88NM-8shlyLpPXrEmcWBoPPMaDg_De_w.qS3YdrTaHLnpW9evdKTKCw";

  private static final String jwt3 =
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkFQUF9XUElfQVBJR0VFXzAxIiwicGkuYXRtIjoiMm9pZyJ9.eyJzY29wZSI6IiIsImNsaWVudF9pZCI6IndwaV9lMDA0MDBfYXBpZ2VlXzAxIiwiaXNzIjoidXJuOi8vYXBpZ2VlLWVkZ2UtSldULXBvbGljeS10ZXN0IiwiYXVkIjoidXJuOi8vYzYwNTExYzAtMTJhMi00NzNjLTgwZmQtNDI1MjhlYjY1YTZhIiwic3ViIjoiYXBpZ2VlLXNlYXR0bGUtaGF0cmFjay1tb250YWdlIiwiZXhwIjoxNTczNTc5MzYxfQ.A-GoVl4h0nys-5lI_p2_71iEfu2YUYPvJVeoZfWDwoDITAvJV0ejyQ0J9w2rgsA-t0cfTlY1t-dAPg3hfuExVBeg2QibNqwaJSy5YlxCadaSxIBF7jYCnYJbVAI300uygm3J4rYnjaeaS1wKpSHRYKCBMEbQonqk5L_xhR7q9oWcBewqiEWA0f4fqGVrTBhfb1bqb8Fynzf2ohtxScec1aJ2dHaGRy5rcmIgV_ezY6A6tT_aawgUEAylTs90hliaG5EJ5_FaMHG9phEgUjwXw695X8qkcmAu_PP2yjjVEAhIUCLNJvqD1tcHip71roLwHNZSBIJVuGk_xL6oFnA_oQ";

  private static final String jwe1 =
      "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJwaS5hdG0iOiIyb2lnIn0.ZJD2tK-HTL9NDxCY6_aL9WS7OrwxvnHpQ73wLQ9bZs4JXSb4Xr3LtKlDAQ-9FajhnKFB8K-wj_bpF4Ir3548ipVlihh8gNtC_LVIi2S3iSP3bBZ6ozmEu29Mow1wT6fHn7Qwok0n8misUzZnV0a81RmGj5WenQze8OLTkNtZDWaS6Gr1YjQz_M5vqXrIbIzNfSYbFmSL0poVcs966ok78Br3GIhH1RfsMlBdpodRzqh8nQ-LJ7hfciun06Udlb9CgvtT8ODxXULa57m22Y3-3q_ljIWVrTbVvZ9Targ23LSwfj6lXKTdYeiRZqiv9OEgm5TJuetl5WULV_sqrdgZ1w.dedzaIHfMzY7kjGJ.oHzVKnxUxdZrnrsiOCPg49Gi3N6HxW4XSupcMzUG81L9Bw-Ih49Jo_sDqLXkOpwP7RAqvhyF3-3uumd5oSqpknmTaSUE3eOqFQ3Es06vYUVATc2xwwH0ehJh4DJm4hzoXROrKOJzKMrZj0636pCl-Yj0X0sx-1ktC4IdlnJV4Uela7isi1JKqX-WaxCRRTYdwiVvBTNIuRRfGCs9I8B6yt_lNeU4kW-aZ56AyLMl3oETqenEFU7CM7v4UARwiShlh3eWWGHzsuT66ofRrwWgRNM0U7JoRV8yUFEpIaQeTuLkPqWPzrVyAHB62smnYMOy2JQKfXMW7IqzymadwL5hE4Gf2XZNrs8cm4ajqbHo0n0dNsHzjnaqb3dCp6pQnYk3Uy0uPkRw8DikM39IcfhuolaZghVYtQ3kyB6Ub3QoEurAEoNyRefJ3h-VHzF8yilNeI3Ay4aA57fzHI2H11M9Pu9YEBMGgpPa7DJnbFzV5nE1H-GkHzUjvJmj6_-rlmHcTC1_55eCzY-zHOHiUsgKiIwLVcqEBxtPxD2D_xZcwRHtSF_ixvUlreGTxYZC-8n2Hu2Ny8FlpRY1NSM-sJrtSyo2lh-a6mjAFGU0TltLcOdMbsroB8UmE0zSmKSXTn3QR60b44yjxHO_o77MbBFUuIOuXV9L-E1b-CmHFg2BV7_1vshdKcucbjvhEKvKZNZ9OQBdTeqPRiBqJlCbHd9NJPXu96OVamP7Oz5oLBhWBJksG1Z1wEJAwoT6SgbcZNZiIgBIb5jGHa894hz-B79UM6E9bmD5k497XXQNGdCeISssBeP9xXzGQs8ZZPJ2i8LnpJykvQJvrcfPfYrQnR6ozg_EY9p88eAbxvqWHGpIvgyvV6G6moV1yi17BtkGRjQVbfNHsK_L-wBt1A.vnBwrK3690tYkgmmM08wog";

  private String privateKey3 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRAfA4ZxT2b2Hr\n"
          + "kbcKXrcMuWJTjfyq50BL+C+VcXGHKmzqw/TAq+3XwATEC+7D9Cf0CssJ93sp/vu+\n"
          + "vqDtIcokqaro+mU9otWHKLN4W2+emw244g/Zj0T3P5n+ikTcEjWoX4tiGoawBJVR\n"
          + "InyKG58EvvZ59reHbTy/6UAYi95W1kGzeKqdNsSYWvHaPsOetMzWhnJlHGSLPjml\n"
          + "1oxETp/5ALyCv92vREEu10ND6LehX7GYbE06FrPdTH0oKuFiwm0p6mhbQQPd1yXH\n"
          + "00GMMVEx+aNUHy5qVZ5HYjTuXJ9Fg4UsCjF8gVTWnT+luMAkTjYTLvrHe/l7Fbkw\n"
          + "j0Hp4Yv9AgMBAAECggEBAMs9B0rRciDwzlczqrn6wCUvX93ABCJsHKnC/QJk/fBh\n"
          + "4OepBScWCIHzxq6cq+EAWpmEpUtby/haapJg7Duqz9Y25msGkcwNu3VirqIqx6+D\n"
          + "NyTBLohwOK/0uNo7uhoF2wePYQpUoQQocMokrtXdZhRHXYXb0zttjdVQC3PTDrGA\n"
          + "g8sP1cXsEYkXrngjlc6O2UJVo3AF3gaI2dpAOT5HniUgtyQcLjQksoE+12edbNyZ\n"
          + "UZpHnQ31t54skilwamZbUkxPGyyBDbifjR9t7MwUatPUDmX+O9U9oiDjdxiGkAS7\n"
          + "EGED8GvZXFneu1L8Q8N+akOigNI6fsNQ+deJmdChzAECgYEA+fieahm7/ibzhO3s\n"
          + "mnD2O7KqYCpm3RxPeGF2jvGVm2UoIiS3UuvI4PErp6eHH+hDzXdjF8w9p3LZXO0p\n"
          + "ZXnBNpDb2+EkUE2CK41Q0N2jJNuwrykP8hSknpt3ArdbeV2/MP0E/u/0PNwsUFsi\n"
          + "IAh9wYRwNfr2sgg1GoOzqU9gec0CgYEA1gxmjpUVQgUAn1Bi0NvXeTnH/qrkhUMz\n"
          + "AvEZygoGvQ34PYmY4+i/q+5Jnu1Yk5G/uwtGTZLLNRXI/lWawpVcxIvwgMwC4wXV\n"
          + "kKHAiw7U6QKKocs95AJrbPEeU1TmohmZLlewGBHAB4LpruH8R0i7guHdBgRkj2ET\n"
          + "JmLNIRQgavECgYA3HXxARKBQr2HuI0+R1epUy1YJkg/QHNfg4Qx1BAtKkglBTfsl\n"
          + "y1slTcekVanTfTDF8tbkfmHxs779YEVKXIgfcd0oJAIPuqdC1wvEobnA/Ld+R31+\n"
          + "kNKjLgAVlzwSDHuFX6RkWZ/uc1VJ+m4Rxg2ER6E+JbGTG4Ap8nQAlsHc2QKBgQDA\n"
          + "d1wMXy9DMt5RYmXIKbWBcpxLePyMe1U2Evc+fW97tUD+jGgmnpUiktwuBHr+DjMZ\n"
          + "i9TGUfVYoWMelnjW+Jj2vmIeXdNGsWtMZrWMFGULs9ZWDztyd16DEfhTs+bB4USk\n"
          + "sAJOUj+aQXPAZcGDk3nQASnNjEujxQUEIhkS4lcX8QKBgDzlG9jCZJG74qP2H9sO\n"
          + "a6oHhpK6VeJUE9BbrcQSz1wMqvwG2hO5BktkP1OB0feXVcKxpoYr1ICRFXxELOuH\n"
          + "j4VXfJ+9BuUhLbrPdpEPbYp4zIbJSI1D2p4dz66qFROVBcxb3xhoySZw3lqtJ55+\n"
          + "R73rOenoHWcqj+zNux9E58mV\n"
          + "-----END PRIVATE KEY-----\n";

  private static final String cert1 =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIDXDCCAkSgAwIBAgIGAWn9XZcJMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNVBAYT\n"
          + "AlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gx\n"
          + "DDAKBgNVBAoTA1BOQzEMMAoGA1UECxMDSUFNMRgwFgYDVQQDEw9KV1RUb2tlblNp\n"
          + "Z25pbmcwHhcNMTkwNDA4MTQzMjQzWhcNMjkwNDA1MTQzMjQzWjBvMQswCQYDVQQG\n"
          + "EwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdo\n"
          + "MQwwCgYDVQQKEwNQTkMxDDAKBgNVBAsTA0lBTTEYMBYGA1UEAxMPSldUVG9rZW5T\n"
          + "aWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4wHpttVyywq\n"
          + "ovOj4BqJrkE7hiWXcj5fPcToSsNXObxYbSjIDAgF62Tdd3gDA0PNhLju7abjcF8d\n"
          + "NU20G9ElsMe4SH9enHZ3wQANcUcQ454iFKwdAzycWI7iWBrwT5ro5Dy30NaN7vNu\n"
          + "K/17C+eN0d7+rrB44SCya5ByUl//6BGtFiGh96+ZwADIKLjluBn+pMX/6LYA5rHV\n"
          + "NXWomhTJ3ZjEiSCSaeRR7PkL+N9okIjAt30mE5MaPU0Lsn88nxk9qsYuYIhjfGOs\n"
          + "k3pKErAvwSuRL37XMhnA4f5QbRuVOLPSQtPlVabbMPjunLeXJIQX6kkBo2D5xVLx\n"
          + "anfpxOeerQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAclOdE2mUvxkvenKAntL3c\n"
          + "54sMkJLe+WJSHhYLujctaLj3dSIh3rtn0HtW9HQc28vbWakCpold8E8OVCKiv4sI\n"
          + "OlmNwZi9j4ZI3J7h4lShuicqgELEmlvusbvlyGS6fE3Zd4myKhceeglSIX4eYIMI\n"
          + "+GK+2+oHnM823E8cAcuPUY3+L0u9S1wX7YOVUW+44Kl4RUnkC0fYEOpqe8yvR0sj\n"
          + "NiOuwzlhEsDzzDZ6Hmnmh9GVubhmivJdp7/sROWawh6yUkvwgA9lf6no0bp/Wh55\n"
          + "AUSfkBBboTdFvB4itkJOCxuRxO5is06M47F7aYL2XT6ESY+C+fZO3NLhCs+7XkWC\n"
          + "-----END CERTIFICATE-----\n";

  private void reportThings(Map<String, String> props) {
    String test = props.get("testname");
    System.out.println("test  : " + test);
    String header = msgCtxt.getVariable("ejwt_header");
    System.out.println("header: " + header);
    String payload = msgCtxt.getVariable("ejwt_payload");
    System.out.println("payload: " + payload);

    String alg = msgCtxt.getVariable("ejwt_alg");
    System.out.println("alg: " + alg);

    String enc = msgCtxt.getVariable("ejwt_enc");
    System.out.println("enc: " + enc);

    String error = msgCtxt.getVariable("ejwt_error");
    System.out.println("error : " + error);
  }

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
