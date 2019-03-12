package com.xp.paytest.adapter;

import com.xp.paytest.interceptor.AliPayInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


/**
 * @author XP
 * @date 2018/6/4 21:59
 */
@Configuration
public class PayWebMvcConfigurerAdapter implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry){
        registry.addInterceptor(new AliPayInterceptor()).addPathPatterns("/alipay/**");
    }
}
