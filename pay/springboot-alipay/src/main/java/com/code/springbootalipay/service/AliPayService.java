package com.code.springbootalipay.service;

import com.alipay.api.AlipayResponse;
import com.alipay.api.response.AlipayTradePrecreateResponse;
import com.alipay.demo.trade.config.Configs;
import com.alipay.demo.trade.model.ExtendParams;
import com.alipay.demo.trade.model.GoodsDetail;
import com.alipay.demo.trade.model.builder.AlipayTradePrecreateRequestBuilder;
import com.alipay.demo.trade.model.result.AlipayF2FPrecreateResult;
import com.alipay.demo.trade.service.AlipayTradeService;
import com.alipay.demo.trade.service.impl.AlipayTradeServiceImpl;
import com.alipay.demo.trade.utils.ZxingUtils;
import com.code.springbootalipay.pojo.Order;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author: liyufei
 * @date: 2018-05-19 17:48
 */
@Service
public class AliPayService {

    private static final Logger logger = LoggerFactory.getLogger(AliPayService.class);

    @Value("${alipay.callback.url}")
    private String alipayCallbackUrl;

    /**
     * 支付宝生成二维码
     * @param orderNo   订单id
     * @param userId    当前用户id
     * @param uploadPath    生成的支付二维码上传FTP的地址
     */
    public String alipay(Long orderNo, Integer userId, String uploadPath) {
        Map<String, String> resultMap = new HashMap<>();
        // 根据userId和orderNo到数据库查询订单是否存在。。。
        resultMap.put("orderNo", String.valueOf(orderNo));

        // (必填) 商户网站订单系统中唯一订单号，64个字符以内，只能包含字母、数字、下划线，
        // 需保证商户系统端不能重复，建议通过数据库sequence生成，
        String outTradeNo = String.valueOf(orderNo);

        // (必填) 订单标题，粗略描述用户的支付目的。如“xxx品牌xxx门店当面付扫码消费”
        String subject = new StringBuilder().append("支付宝扫码支付,订单号:").append(outTradeNo).toString();

        // (必填) 订单总金额，单位为元，不能超过1亿元
        // 如果同时传入了【打折金额】,【不可打折金额】,【订单总金额】三者,则必须满足如下条件:【订单总金额】=【打折金额】+【不可打折金额】
        String totalAmount = "0.01";

        // (可选) 订单不可打折金额，可以配合商家平台配置折扣活动，如果酒水不参与打折，则将对应金额填写至此字段
        // 如果该值未传入,但传入了【订单总金额】,【打折金额】,则该值默认为【订单总金额】-【打折金额】
        String undiscountableAmount = "0";

        // 卖家支付宝账号ID，用于支持一个签约账号下支持打款到不同的收款账号，(打款到sellerId对应的支付宝账号)
        // 如果该字段为空，则默认为与支付宝签约的商户的PID，也就是appid对应的PID
        String sellerId = "";

        // 订单描述，可以对交易或商品进行一个详细地描述，比如填写"购买商品2件共15.00元"
        String body = new StringBuilder().append("订单").append(outTradeNo).append("购买商品共").append(totalAmount).toString();

        // 商户操作员编号，添加此参数可以为商户操作员做销售统计
        String operatorId = "test_operator_id";

        // (必填) 商户门店编号，通过门店号和商家后台可以配置精准到门店的折扣信息，详询支付宝技术支持
        String storeId = "test_store_id";

        // 业务扩展参数，目前可添加由支付宝分配的系统商编号(通过setSysServiceProviderId方法)，详情请咨询支付宝技术支持
        ExtendParams extendParams = new ExtendParams();
        extendParams.setSysServiceProviderId("2088100200300400500");

        // 支付超时，定义为120分钟
        String timeoutExpress = "120m";

        // 商品明细列表，需填写购买商品详细信息，
        List<GoodsDetail> goodsDetailList = new ArrayList<GoodsDetail>();
        // 创建一个商品信息，参数含义分别为商品id（使用国标）、名称、单价（单位为分）、数量，如果需要添加商品类别，详见GoodsDetail
        GoodsDetail goods1 = GoodsDetail.newInstance("goods_id001", "xxx小面包", 1000, 1);
        // 创建好一个商品后添加至商品明细列表
        goodsDetailList.add(goods1);

        // 继续创建并添加第一条商品信息，用户购买的产品为“黑人牙刷”，单价为5.00元，购买了两件
        GoodsDetail goods2 = GoodsDetail.newInstance("goods_id002", "xxx牙刷", 500, 2);
        goodsDetailList.add(goods2);

        // 创建扫码支付请求builder，设置请求参数
        AlipayTradePrecreateRequestBuilder builder = new AlipayTradePrecreateRequestBuilder()
                .setSubject(subject).setTotalAmount(totalAmount).setOutTradeNo(outTradeNo)
                .setUndiscountableAmount(undiscountableAmount).setSellerId(sellerId).setBody(body)
                .setOperatorId(operatorId).setStoreId(storeId).setExtendParams(extendParams)
                .setTimeoutExpress(timeoutExpress)
                .setNotifyUrl(alipayCallbackUrl)//支付宝服务器主动通知商户服务器里指定的页面http路径,根据需要设置
                .setGoodsDetailList(goodsDetailList);

        Configs.init("zfbinfo.properties");
        AlipayTradeService tradeService = new AlipayTradeServiceImpl.ClientBuilder().build();
        AlipayF2FPrecreateResult result = tradeService.tradePrecreate(builder);
        switch (result.getTradeStatus()) {
            case SUCCESS:
                logger.info("支付宝预下单成功: )");
                AlipayTradePrecreateResponse response = result.getResponse();
                dumpResponse(response);

                File folder = new File(uploadPath);
                if (!folder.exists()) {
                    folder.setWritable(true);
                    folder.mkdirs();
                }
                // 需要修改为运行机器上的路径
                String qrPath = String.format(uploadPath + "/qr-%s.png", response.getOutTradeNo());
                ZxingUtils.getQRCodeImge(response.getQrCode(), 256, qrPath);

                // String qrFileName = String.format("qr-%s.png", response.getOutTradeNo());
                // 将生成的二维码上传到七牛云，然后将二维码url地址返回给前端展示
                logger.info("qrPath:" + qrPath);
                return qrPath;
            case FAILED:
                logger.error("支付宝预下单失败!!!");
                break;
            case UNKNOWN:
                logger.error("系统异常，预下单状态未知!!!");
                break;
            default:
                logger.error("不支持的交易状态，交易返回异常!!!");
                break;
        }
        return null;
    }

    // 简单打印应答
    private void dumpResponse(AlipayResponse response) {
        if (response != null) {
            logger.info(String.format("code:%s, msg:%s", response.getCode(), response.getMsg()));
            if (StringUtils.isNotEmpty(response.getSubCode())) {
                logger.info(String.format("subCode:%s, subMsg:%s", response.getSubCode(),
                        response.getSubMsg()));
            }
            logger.info("body:" + response.getBody());
        }
    }

    public boolean aliCallback(Map<String,String> params){
        /*
        CREATE TABLE `mmall_order` (
          `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '订单id',
          `order_no` bigint(20) DEFAULT NULL COMMENT '订单号',
          `user_id` int(11) DEFAULT NULL COMMENT '用户id',
          `shipping_id` int(11) DEFAULT NULL,
          `payment` decimal(20,2) DEFAULT NULL COMMENT '实际付款金额,单位是元,保留两位小数',
          `payment_type` int(4) DEFAULT NULL COMMENT '支付类型,1-在线支付',
          `postage` int(10) DEFAULT NULL COMMENT '运费,单位是元',
          `status` int(10) DEFAULT NULL COMMENT '订单状态:0-已取消-10-未付款，20-已付款，40-已发货，50-交易成功，60-交易关闭',
          `payment_time` datetime DEFAULT NULL COMMENT '支付时间',
          `send_time` datetime DEFAULT NULL COMMENT '发货时间',
          `end_time` datetime DEFAULT NULL COMMENT '交易完成时间',
          `close_time` datetime DEFAULT NULL COMMENT '交易关闭时间',
          `create_time` datetime DEFAULT NULL COMMENT '创建时间',
          `update_time` datetime DEFAULT NULL COMMENT '更新时间',
          PRIMARY KEY (`id`),
          UNIQUE KEY `order_no_index` (`order_no`) USING BTREE
        ) ENGINE=InnoDB AUTO_INCREMENT=118 DEFAULT CHARSET=utf8;
         */

        Long orderNo = Long.parseLong(params.get("out_trade_no"));
        String tradeNo = params.get("trade_no");
        String tradeStatus = params.get("trade_status");
        logger.info("============支付宝回调日志：============ orderNo: {}, tradeNo: {}, tradeStatus: {}.", orderNo, tradeNo, tradeStatus);
        // 查询数据库订单
        // Order order = orderMapper.selectByOrderNo(orderNo);
        Order dbOrder = new Order();
        dbOrder.setStatus(10); // 这个自定义的状态，主要用于下面测试
        // 如果订单为空，忽略
        if(dbOrder == null){
            // return ServerResponse.createByErrorMessage("非快乐慕商城的订单,回调忽略");
            return false;
        }
        // 如果>=已付款状态的，都表示重复回调了
        if(dbOrder.getStatus() >= 20){
            //return ServerResponse.createBySuccess("支付宝重复调用");
            return false;
        }
        // 校验通过，则更新订单时间和支付状态
        if("TRADE_SUCCESS".equals(tradeStatus)){
            //dbOrder.setPaymentTime(DateTimeUtil.strToDate(params.get("gmt_payment")));
            dbOrder.setStatus(20);
            //orderMapper.updateByPrimaryKeySelective(order);
        }



        /*
        CREATE TABLE `mmall_pay_info` (
          `id` int(11) NOT NULL AUTO_INCREMENT,
          `user_id` int(11) DEFAULT NULL COMMENT '用户id',
          `order_no` bigint(20) DEFAULT NULL COMMENT '订单号',
          `pay_platform` int(10) DEFAULT NULL COMMENT '支付平台:1-支付宝,2-微信',
          `platform_number` varchar(200) DEFAULT NULL COMMENT '支付宝支付流水号',
          `platform_status` varchar(20) DEFAULT NULL COMMENT '支付宝支付状态',
          `create_time` datetime DEFAULT NULL COMMENT '创建时间',
          `update_time` datetime DEFAULT NULL COMMENT '更新时间',
          PRIMARY KEY (`id`)
        ) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8;
         */
        // 插入订单日志
        /*PayInfo payInfo = new PayInfo();
        payInfo.setUserId(order.getUserId());
        payInfo.setOrderNo(order.getOrderNo());
        payInfo.setPayPlatform(Const.PayPlatformEnum.ALIPAY.getCode());
        payInfo.setPlatformNumber(tradeNo);
        payInfo.setPlatformStatus(tradeStatus);
        payInfoMapper.insert(payInfo);*/

        return true;
    }
}
