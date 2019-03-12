package com.code.springbootalipay.controller;

import com.alipay.api.AlipayApiException;
import com.alipay.api.internal.util.AlipaySignature;
import com.alipay.demo.trade.config.Configs;
import com.code.springbootalipay.service.AliPayService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * 支付宝当面付：
 *      比较重要的一个逻辑：
 *      1.生成支付二维码，供用户扫码支付
 *      2.当用户支付成功后，会回调我们后台更新订单状态，减少库存等操作
 *      3.前端轮询查询订单状态，成功返回首页，失败则跳到失败页面等操作
 * @author: liyufei
 * @date: 2018-05-19 17:47
 */
@Controller
public class AliPayController {

    private static final Logger logger = LoggerFactory.getLogger(AliPayController.class);

    @Autowired
    private AliPayService aliPayService;

    @RequestMapping("/to-pay-page")
    public String toPayPage() {
        return "pay";
    }

    /**
     * 1.支付生成二维码，供用户扫码支付
     * @param session   用于获取用户session
     * @param orderNo   待支付订单号
     * @param request   用于获取二维码生成路径
     * @return
     */
    @RequestMapping("/alipay")
    public String alipay(HttpSession session, Long orderNo, HttpServletRequest request, Model model) {
        String qrPath = aliPayService.alipay(orderNo, 1, "D:\\");
        model.addAttribute("qrPath", qrPath);
        return "pay";
    }

    /**
     * 2.支付宝回调方法，当用户扫码并支付成功后，会回调到后台，告诉后台用户付款成功，可以更新订单状态了。
     * @param request
     * @return
     */
    @RequestMapping("/alipay-callback")
    public String alipayCallback(HttpServletRequest request) {
        Map<String, String> params = new HashMap<>();

        Map requestParams = request.getParameterMap();
        for (Iterator iter = requestParams.keySet().iterator(); iter.hasNext(); ) {
            String name = (String) iter.next();
            String[] values = (String[]) requestParams.get(name);
            String valueStr = "";
            for (int i = 0; i < values.length; i++) {
                valueStr = (i == values.length - 1) ? valueStr + values[i] : valueStr + values[i] + ",";
            }
            params.put(name, valueStr);
        }
        logger.info("支付宝回调,sign:{},trade_status:{},参数:{}", params.get("sign"), params.get("trade_status"), params.toString());

        //非常重要,验证回调的正确性,是不是支付宝发的.并且呢还要避免重复通知.
        params.remove("sign_type");
        try {
            boolean alipayRSACheckedV2 = AlipaySignature.rsaCheckV2(params, Configs.getAlipayPublicKey(), "utf-8", Configs.getSignType());
            if (!alipayRSACheckedV2) {
                logger.error("非法请求,验证不通过,再恶意请求我就报警找网警了");
            }
        } catch (AlipayApiException e) {
            logger.error("支付宝验证回调异常", e);
        }

        //todo 验证各种数据

        // 回调业务处理
        boolean aliCallback = aliPayService.aliCallback(params);
        if (aliCallback) {
            // 如果回调成功，并且我们将订单状态都更改成功后，务必一定要给支付宝返回 success 这7个字符，否则支付宝按照一定规则一直重复调用
            // return "success";
        }
        // 如果回调过程中有异常，返回 failed 则表示回调处理失败，需支付宝重新调用回调方法继续处理
        // return "failed";
        return "pay";
    }

    /**
     * 3.前端会轮询调用订单状态，如变为支付成功状态后，跳转到首页等操作
     * @param session
     * @param orderNo
     * @return
     */
    @RequestMapping("query-order-pay-status")
    public String queryOrderPayStatus(HttpSession session, Long orderNo){
        // ServerResponse serverResponse = iOrderService.queryOrderPayStatus(user.getId(),orderNo);
        return "pay";
    }
}















































