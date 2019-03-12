package com.xp.paytest.interceptor;

import com.jpay.alipay.AliPayApiConfigKit;
import com.xp.paytest.Controller.AliPayApiController;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author XP
 * @date 2018/6/4 21:30
 */
public class AliPayInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,Object handler) throws Exception{
        if(HandlerMethod.class.equals(handler.getClass())){
            HandlerMethod method = (HandlerMethod) handler;
            Object controller = method.getBean();
            if(controller instanceof AliPayApiController == false){
                throw new RuntimeException("控制器需要继承 AliPayApiController");
            }
            try{
                AliPayApiConfigKit.setThreadLocalAliPayApiConfig(((AliPayApiController)controller).getApiConfig());
                System.out.println("controller: " + controller);
                return true;
            }finally{

            }
        }
        return false;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o,
                           ModelAndView modelAndView) throws Exception {
    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest,HttpServletResponse httpServletResponse,Object o,Exception e) throws Exception{

    }
}
