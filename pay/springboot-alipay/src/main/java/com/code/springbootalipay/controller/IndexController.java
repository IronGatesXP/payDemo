package com.code.springbootalipay.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author: liyufei
 * @date: 2018-05-19 17:00
 */
@RestController
public class IndexController {

    @GetMapping("/index")
    public String index() {
        return "hello netapp";
    }

}
