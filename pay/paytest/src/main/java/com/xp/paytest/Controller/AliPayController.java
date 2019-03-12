package com.xp.paytest.Controller;

import com.alipay.api.AlipayApiException;
import com.alipay.api.internal.util.AlipaySignature;
import com.jpay.alipay.AliPayApi;
import com.jpay.alipay.AliPayApiConfig;
import com.jpay.util.StringUtils;
import org.slf4j.Logger;
import com.alipay.api.domain.*;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * @author XP
 * @date 2018/6/1 17:04
 */
@Controller
@RequestMapping(value = "/alipay")
public class AliPayController extends AliPayApiController{
    private static final Logger log = LoggerFactory.getLogger(AliPayController.class);
    String appId = "2016102000727659";
    String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuPkP2VJMR6vWCX8RwSFqNIa3klCdvRFJbuS1PN1anzQeeL9eOwtU7kGdI85yxb0dcdPzOYlG+jf9go8W9hBlgjxSRoXxLx03Yfl7cLmzJO9l9vIM1+HmNF0Ctm+el4Yi9dGs/P6q7lcHPUqs/RXGfeLrg33GMVwJbLmRcDZYeIcqPAA1OVF/4SHYr+f+O7glDOd60z+veOOexyoHmvUzYWlEz5+R4kOCNM/Z0w7KGgEYvHbZopexuTuFgUWy/9tYlNrnX+cZUWXVTskLUgD1UGWM1dS5+qfriqY9MPEwJjetcPJkoCK7A4IReE4q1DffUY9KS50/1ML+7na3R/p/UQIDAQAB";
    String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkejVpiLJlece9KLb8gG/+WODkpe5SRfr65n3aUAvRPoouDUp/URBAtt24mzHFdGkaU/Il7ZxG7KUjLaFNTfq8t/bHEF7HBt7MZidpEjVaDxeG/hkA+xc+X2ePAJXVhy7v1tH+XRrxuggTj+d4q7vVGD7r1mtgX4d5hK9TTKnyhO6IUcthPOUSn07wx+5wlbv4/51ggj4Ku4AWCGaCWiebDFy4VZ/FmOMP5u3O7TocCGSy5UtaFZaVMM1nH603DG6NJ8fG+zKum9IvrdQMMmBWPT8rpy0U9ztchcd+0gTNrTfE/NOCgl/RF6z7Qic7NiTKjLxkGRq73XPzfJx0hyfpAgMBAAECggEAa2/sndAN/90JjNUgmlVnUnRKCvEceJ9/rw6KXOV2oqrAZg6GgB26iRsqP6EYZMuCsBDvlrjcITQJNq5is/Vg+I8OYr+duVISjN+ZlLexI+/BxYsLWCmr6DE3myCdvwn7rezb5NR6ejWzetvALoG3Qx4AU9sO7rfX7ZevUrE8Pc5pa/rTCHOIec9P7Hfm4xrXd0DPmbAwFvUQ4spcC9xjcBhLJ3tfmkoEU11jC6Y/J7N0/TZZxqNC+HcYftSNEmbO3vxYfz/9mbabx7Uzp8xs4qHPJACmaP5tcWOCf1qJVOwP53Cd3H9J9Be9cAvlxKfT48s1ghoxLn7QB27p0UwntQKBgQDzTpCCFDoUH328B3iGTkwZq24DOUh5ZwhMG6VIFPLHwJYK6HVM473SX0nJWkbiBYFG4WiQWUZnOhz/qjTH1vvE/nzJwQ79zZahren2b8XulXKM6S/mafiBAHKl/FArcr14iAWkh+scZKWFKrNf6Hp8rQ6zu0fWdwzUOlaQFaSnTwKBgQCtDtpIagRPyNj0J39uMRJqsaY0TdJ53TD4bflf5UiFhNFH2Dikgw/uX8Pom2qtIvf3xnO2bzmJW2+OSkF7U0fL+UXkAaBHW+7YVcs8pWARSd5LWBXGWysV2wUALwynZSdwtgpgrzMQnuzklQ3hNR9LBSEGN7yJwkU83ZRWPzbvRwKBgQDU3E8g/oExSbu+3Opc1fNOIeTFfUAitjlUHHulbG5aw+qA8I5vDm/rtOHg/tI0u4w2bs4EO5aUiQsFwesbSsJJvjt+ZyCue0blfDnMGE2aRbVKAlidxOhcNAAZp3ycBm4tHROStjbDSGpm7syvg7xlhyHtrFNVFiJrKf7BX64FkQKBgCA8lAzJMuRp1YAlm2c7XOLjFMLJfFuXCHg+hCWI4Gl+xD1N2b9LarxMuoGp8cUurmJJZWSmc2FS1wT6cBg4+zbTyGEgrGqehW9nC+TQKYUO7Ym7btL0SKJZmiTenszP2vjz8Bryh+CguiAaY+t/qcSfv/cYitZeiec8n1UxkVohAoGAa8YwnzkEGBgz0TpdrGFxVBCqMIriMH4PQs2tWZ1nEBk6A7GrODRcRL0FQnRpHyf3mY5N/iEiNQ5GhQ5p1lifTvolTkVkdHpTGFhVfnYegaEAOznigi7dWJPoYlloN36AROxirGJKRIm+Od2bsybM/dNPJfoTDBDPFWGBH/klEBs=";
    String serviceUrl = "https://openapi.alipaydev.com/gateway.do";

    @Override
    public AliPayApiConfig getApiConfig(){
        log.info("getConfig函数执行");
        return AliPayApiConfig.New()
                .setAppId(appId)
                .setAlipayPublicKey(publicKey)
                .setCharset("UTF-8")
                .setPrivateKey(privateKey)
                .setServiceUrl(serviceUrl)
                .setSignType("RSA2")
                .build();
    }


    @RequestMapping("")
    @ResponseBody
    public String hello(){
        log.info("输出hello world");
        return "hello world";
    }

    @RequestMapping(value = "/pcPay")
    @ResponseBody
    public void pcPay(HttpServletResponse response){
        try{
//            AliPayApiConfig aliPayApiConfig = getApiConfig();
//            System.out.println("appId is: " + aliPayApiConfig.getAppId());
            String totalAmount = "6";
            // String outTradeNo = StringUtils.getOutTradeNo();
            String outTradeNo = "060418002615290";
            log.info("pc outTradeNo>"+outTradeNo);
            String returnUrl =  "http://127.0.0.1:8080/alipay/return_url";
            String notifyUrl =  "http://127.0.0.1:8080/alipay/notify_url";
            AlipayTradePayModel model = new AlipayTradePayModel();
            model.setOutTradeNo(outTradeNo);
            model.setProductCode("FAST_INSTANT_TRADE_PAY");
            model.setTotalAmount(totalAmount);
            model.setSubject("PC支付测试");
            model.setBody("paytest PC支付测试");
            System.out.println("到这里model设置完毕");
            AliPayApi.tradePage(response,model,notifyUrl,returnUrl);
        }catch(Exception e){
            e.printStackTrace();
            e.getMessage();
        }
    }

    @RequestMapping(value = "/return_url")
    @ResponseBody
    public String return_url(HttpServletRequest request,HttpServletResponse response)throws IOException {
        try {
//            response.getWriter().write("xp");
//            response.getWriter().flush();
//            response.getWriter().close();
            // 获取支付宝GET过来反馈信息
            Map<String, String> map = AliPayApi.toMap(request);
            for (Map.Entry<String, String> entry : map.entrySet()) {
                System.out.println(entry.getKey() + " = " + entry.getValue());
            }

            boolean verify_result = AlipaySignature.rsaCheckV1(map, publicKey, "UTF-8",
                    "RSA2");

            if (verify_result) {// 验证成功
                // TODO 请在这里加上商户的业务逻辑程序代码
                System.out.println("return_url 验证成功");

                return "success";


            } else {
                System.out.println("return_url 验证失败");
                // TODO
                return "failure";
            }
        } catch (AlipayApiException e) {
            e.printStackTrace();
            return "failure";
        }
    }

}
