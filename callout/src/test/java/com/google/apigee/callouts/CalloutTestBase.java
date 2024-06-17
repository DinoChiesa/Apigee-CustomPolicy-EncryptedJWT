// CalloutTestBase.java
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

import com.google.apigee.fakes.FakeExecutionContext;
import com.google.apigee.fakes.FakeMessage;
import com.google.apigee.fakes.FakeMessageContext;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Random;
import org.testng.annotations.BeforeMethod;

public abstract class CalloutTestBase {

  static {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }

  FakeMessage message;
  FakeMessageContext msgCtxt;
  FakeExecutionContext exeCtxt;

  @BeforeMethod
  public void beforeMethod(Method method) throws Exception {
    String methodName = method.getName();
    String className = method.getDeclaringClass().getName();
    System.out.printf("\n\n==================================================================\n");
    System.out.printf("TEST %s.%s()\n", className, methodName);

    message = new FakeMessage();
    msgCtxt = new FakeMessageContext(message);
    exeCtxt = new FakeExecutionContext();
  }

  protected static final String privateKey1 =
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

  protected final String privateKey2 =
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

  protected static final String privateKey3 =
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

  protected static final String privateKey4 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrXfjCAfJR8K+9\n"
          + "2rvB67ZyaGRdvSn3+NZdcEOxl0IV4f7YK5PockjcQVmaTmj6XfS4X8OTWi8EbdLZ\n"
          + "yaVa9CVL7ex7XhGXifoqUZW2o93fPPm015JGLei8LZhMIxLYma7hrGqh19kk9mwI\n"
          + "8nIWKRcZlgujexHjkyeDV0yv4gpSFBOiDB7iUdv5+SoRrJHZkRF2eFIeVihvhrCu\n"
          + "z6p4hOQAXwBRJhGqSodZnL1JsQMaI6RFw2ZrK9JOR1CxNWTAZpyxKZ+wyI6RHyLo\n"
          + "trjtF/koZqPChROU6Bm6FifcL9Yod/LBDzmTo2QQjB2HQbPIdo1VFVLBKuNzeBwb\n"
          + "gUQsXqjhAgMBAAECggEACC3cCaZ+IlsSiEVAYOkXNC63W6IDtsoxsRQCpx9JEDJR\n"
          + "L5Ak5xtNTvXviOXlLM3/OC2Z8BaF1/hF8A8nzUeJ4C3i86BxxoHXZt2t/6GinV0T\n"
          + "rgX7/U2Dpjem5TtnUt9C8ZKBJGhg/NqmHWc0+snLSHVY6Nye5fXIFQS9rEdlprUq\n"
          + "kEj0nFUSrp1bo5jLTH4nXv5Rca+OMwge3Bv9Gpq2wk0IKLSHLBMLzDPfOMyUZ6Tc\n"
          + "dWqwYbbj2pXpSy87YN6Bfzmp7wS5X3xLl9gaEFFaLV6GkV3SkUCvi5ZmwfAQXxNB\n"
          + "HNltMxDBuFQkr+DKyYxol9fwKtEOa4n4QFfONZTKAQKBgQDgRYieLaPvqtwTrrAi\n"
          + "1NV0CgVb6GYWAHC3JIRAqmqKMlyEiEvbsZ6zs0ZIMdQ4MSw0NUmZoD/2F1a32sg/\n"
          + "qUauW9dQkVgbGGKQQ36d0ulIx/rE9f7qX7rZZN2hS2C516elRveCIQ9JYtx3ECk2\n"
          + "NWcl43u5mh8OS/IN881cfXtvyQKBgQDDnGOsy3UKx5S4BvX6CylLKTNqwKi3Nuqb\n"
          + "kUN1DPjZESMEzwQfqURjwI3UTT1EWCrTZake7a6DtID5pe7mOlN2DGM8vAepeEXQ\n"
          + "gY+vCYjWdKkXxPZz7Dw+rHfXuX+y+XAKr5KjcCB61cyz4q2NGLDyjbXANgFBdrbZ\n"
          + "llkEDOxsWQKBgCAzm7QqlXlaLRNeZ8f4i1WIAtD5g37xPT3urlaioX2KUaJt94Zp\n"
          + "8IGY4iSHkxMmbFRqulCmo8hv/XGUpmANrCpo4XeeBuqNC8nvBwUePYTHwgf50kpQ\n"
          + "yIFibDg2nILSpi2jDPLQUGOXIFSwK1qvPEpCaYdyy7a/zNeYBAqdsdWRAoGAdLNJ\n"
          + "uB5N/pdhf4UPnRSplyDGfyrfvSazQwqgHyYVFJOnu8ex4x2+InEPbJiEM9ESA7rD\n"
          + "8iLFGehHhilb5NjpUCVF00cunwmVRTb2vOvISoGhHAAzNKe8rXuBqB8QM3ujP4zN\n"
          + "xFox1nbVQIC9H8+aSasHwtu1VhP4NMoA42y+ZEkCgYEAjsBNBC8kMpkQ+VsfOUsO\n"
          + "cqZDycBmlneHVRGZLGh9eqxtXXh3wy+K6iPmSe6diiaybMXsAB9v7ANQ69J3NKiq\n"
          + "n2lLRavhhA+nWaF0/Fc0oYZf/JwVLlMe7CohwwUvUNMLMxMTy1ljrHcRbSYYlUbW\n"
          + "oBnc5zrx3gR1tTtj8rqkK/E=\n"
          + "-----END PRIVATE KEY-----\n";

  protected static final String ecPrivateKey1 =
      "-----BEGIN PRIVATE KEY-----\n"
          + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVA7GiMpmiyDgxESR\n"
          + "B7bDPrKp7Fa3UQZ7Zlnox/oa6dahRANCAARgVnYkM38ondUD34Zw5PcJ5lsBV+ji\n"
          + "Fk+BBhvDxhCFQvFmDG8WXN1LaZVivkfAMptbIgruT3MtzaSxqHeta/65\n"
          + "-----END PRIVATE KEY-----\n";

  protected static final String ecPublicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYFZ2JDN/KJ3VA9+GcOT3CeZbAVfo\n"
          + "4hZPgQYbw8YQhULxZgxvFlzdS2mVYr5HwDKbWyIK7k9zLc2ksah3rWv+uQ==\n"
          + "-----END PUBLIC KEY-----\n";

  protected static final String publicKey1 =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA15PZNNSa4RkH9eAeJ8ph\n"
          + "57WhvUmANpBEDqP0SuHzNl3HmxbEiUPBoBNQAtRpVlOWM0t+FltMORjGXtntjSBs\n"
          + "/8do3kaPbKN4Ua0O/wRpe15wHnRBNT+V5qonUDy0R+gfBqBpMNVIn2b1x5EWih10\n"
          + "sMCU+rjnUvBYtCGHmbQlUcZOZbXLSWfV3ukoRaGG2KV9V2zNXWjTZiKSFRFJZSeW\n"
          + "4sT+s9twcmx+QF60xkpqe4/DvrqanKb3bKGQoViC0wl67vzv+QfaLtku/WAsBeLm\n"
          + "I3DFmXb0ny3uCUCfCRtHnpAU0gfjWBiwkZ/R2OhZOW877GGcNMKVTnFT6911gGMi\n"
          + "SwIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  protected static final String jwt1 =
      "eyJ0eXAiOiJKV1QiLCJoZHIxIjoxMjMsImVuYyI6IkExMjhHQ00iLCJoZHIyIjp0cnVlLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.n3CicDJeNIdfRHuS9XBAvP1Sep2eyiEIPgvodY4BxzUfUEKxPnWvPVSx-ikaxan5Oi_PSqipIdnPSBJ7pNN1Rt4aqFEBBW5m0WCUwsssyLP0A_MD8usUVg0VqRqBFXqokbTIEO7YCXxGP-bXs-I_1eeuqN12-OokkcWJtyf-n8-HHpp-DAc8xQkYB5oQZqC5rGGAWJh0tThSkynepvJzymaXETiO69B6vU6Oe2VL2PWgMYoB3YjfdEKSZelFe7dLd14G_G5sDKkA33vHjC3w9OPAHlubYpZnWuBdrLH9sV-YSkyLRtiWc-rG1eHIFODcbUXqiDBrhPSfWJlf6wd1_Q.mRqogt0pxtPdgyjt.73XlhsvhcsaIFJUrqZFyf0Hjgxx9A-rbPWoIdsup-ScsXuqO6RevhNdjBg.ESdhCa_eqd2FaI5e5IH2xQ";

  protected static final String jwt2 =
      "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.vqVKvZcGr7b7MWzSCmYUVXolSTXW-eCzN_ly03gzix47HBYkk7-nQ_kocdeLOr_qV3pTusJedfq6RyeSsccCu0aJionCureBxtn9udM2MZ1OCNmGIBJhWxDqAKIYOmB_IwTK6ATGRRiqOssw1y1x4PWH13QT_Jxf0VuWDZXm74Cz_ttL_dmtZp7zIM47imjUxRhOCdLdBtYkT2Q-9r__WHq1XOVuYiuLaMBnJ3YPtONhwHbyAJ1TshDgkffllivRs9qs7ONy6fvc9OlYkEoUs2zYGAupMUX1YHSnS62ASnEUMcq9lJsxK32Rvh-DmchgtTMvOH1hBoFnuzzi6p3crg.BRTKgJtcL3mLplCd.8lu-rdSOiH_Qvt0KOM6MxuYkf096ldFGuOiCJigzJxQWMyY4UTNkkkl_FFK4bO76w46c5Ub66l3AXWxT9OwwX4A3KwaDI9USEfRUBuXW3S7fSmVrjEu88NM-8shlyLpPXrEmcWBoPPMaDg_De_w.qS3YdrTaHLnpW9evdKTKCw";

  protected static final String jwt3 =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6IkFQUF9XUElfQVBJR0VFXzAxIiwicGkuYXRtIjoiMm9pZyJ9.eyJzY29wZSI6IiIsImNsaWVudF9pZCI6IndwaV9lMDA0MDBfYXBpZ2VlXzAxIiwiaXNzIjoidXJuOi8vYXBpZ2VlLWVkZ2UtSldULXBvbGljeS10ZXN0IiwiYXVkIjoidXJuOi8vYzYwNTExYzAtMTJhMi00NzNjLTgwZmQtNDI1MjhlYjY1YTZhIiwic3ViIjoiYXBpZ2VlLXNlYXR0bGUtaGF0cmFjay1tb250YWdlIiwiZXhwIjoxNTczNTc5MzYxfQ.A-GoVl4h0nys-5lI_p2_71iEfu2YUYPvJVeoZfWDwoDITAvJV0ejyQ0J9w2rgsA-t0cfTlY1t-dAPg3hfuExVBeg2QibNqwaJSy5YlxCadaSxIBF7jYCnYJbVAI300uygm3J4rYnjaeaS1wKpSHRYKCBMEbQonqk5L_xhR7q9oWcBewqiEWA0f4fqGVrTBhfb1bqb8Fynzf2ohtxScec1aJ2dHaGRy5rcmIgV_ezY6A6tT_aawgUEAylTs90hliaG5EJ5_FaMHG9phEgUjwXw695X8qkcmAu_PP2yjjVEAhIUCLNJvqD1tcHip71roLwHNZSBIJVuGk_xL6oFnA_oQ";

  protected static final String jwe1 =
      "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJjdHkiOiJKV1QiLCJwaS5hdG0iOiIyb2lnIn0.ZJD2tK-HTL9NDxCY6_aL9WS7OrwxvnHpQ73wLQ9bZs4JXSb4Xr3LtKlDAQ-9FajhnKFB8K-wj_bpF4Ir3548ipVlihh8gNtC_LVIi2S3iSP3bBZ6ozmEu29Mow1wT6fHn7Qwok0n8misUzZnV0a81RmGj5WenQze8OLTkNtZDWaS6Gr1YjQz_M5vqXrIbIzNfSYbFmSL0poVcs966ok78Br3GIhH1RfsMlBdpodRzqh8nQ-LJ7hfciun06Udlb9CgvtT8ODxXULa57m22Y3-3q_ljIWVrTbVvZ9Targ23LSwfj6lXKTdYeiRZqiv9OEgm5TJuetl5WULV_sqrdgZ1w.dedzaIHfMzY7kjGJ.oHzVKnxUxdZrnrsiOCPg49Gi3N6HxW4XSupcMzUG81L9Bw-Ih49Jo_sDqLXkOpwP7RAqvhyF3-3uumd5oSqpknmTaSUE3eOqFQ3Es06vYUVATc2xwwH0ehJh4DJm4hzoXROrKOJzKMrZj0636pCl-Yj0X0sx-1ktC4IdlnJV4Uela7isi1JKqX-WaxCRRTYdwiVvBTNIuRRfGCs9I8B6yt_lNeU4kW-aZ56AyLMl3oETqenEFU7CM7v4UARwiShlh3eWWGHzsuT66ofRrwWgRNM0U7JoRV8yUFEpIaQeTuLkPqWPzrVyAHB62smnYMOy2JQKfXMW7IqzymadwL5hE4Gf2XZNrs8cm4ajqbHo0n0dNsHzjnaqb3dCp6pQnYk3Uy0uPkRw8DikM39IcfhuolaZghVYtQ3kyB6Ub3QoEurAEoNyRefJ3h-VHzF8yilNeI3Ay4aA57fzHI2H11M9Pu9YEBMGgpPa7DJnbFzV5nE1H-GkHzUjvJmj6_-rlmHcTC1_55eCzY-zHOHiUsgKiIwLVcqEBxtPxD2D_xZcwRHtSF_ixvUlreGTxYZC-8n2Hu2Ny8FlpRY1NSM-sJrtSyo2lh-a6mjAFGU0TltLcOdMbsroB8UmE0zSmKSXTn3QR60b44yjxHO_o77MbBFUuIOuXV9L-E1b-CmHFg2BV7_1vshdKcucbjvhEKvKZNZ9OQBdTeqPRiBqJlCbHd9NJPXu96OVamP7Oz5oLBhWBJksG1Z1wEJAwoT6SgbcZNZiIgBIb5jGHa894hz-B79UM6E9bmD5k497XXQNGdCeISssBeP9xXzGQs8ZZPJ2i8LnpJykvQJvrcfPfYrQnR6ozg_EY9p88eAbxvqWHGpIvgyvV6G6moV1yi17BtkGRjQVbfNHsK_L-wBt1A.vnBwrK3690tYkgmmM08wog";

  protected static final String cert1 =
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

  protected static final String gettysburg =
      "Four score and seven years ago our fathers brought forth on this continent, a new nation,"
          + " conceived in Liberty, and dedicated to the proposition that all men are created"
          + " equal. Now we are engaged in a great civil war, testing whether that nation, or any"
          + " nation so conceived and so dedicated, can long endure. We are met on a great"
          + " battle-field of that war. We have come to dedicate a portion of that field, as a"
          + " final resting place for those who here gave their lives that that nation might live."
          + " But, in a larger sense, we can not dedicate — we can not consecrate — we can not"
          + " hallow — this ground.";

  protected void reportThings(String prefix, Map<String, String> props) {
    String test = props.get("testname");
    System.out.println("test   : " + test);
    String header = (String) msgCtxt.getVariable(prefix + "_header");
    System.out.println("header : " + header);
    String payload = (String) msgCtxt.getVariable(prefix + "_payload");
    System.out.println("payload: " + payload);

    String alg = (String) msgCtxt.getVariable(prefix + "_alg");
    System.out.println("alg    : " + alg);

    String enc = (String) msgCtxt.getVariable(prefix + "_enc");
    System.out.println("enc    : " + enc);

    String error = (String) msgCtxt.getVariable(prefix + "_error");
    System.out.println("error  : " + error);
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
}
