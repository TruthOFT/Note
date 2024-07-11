package com.note.controller;

import com.note.entity.RestBean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/hello")
    @ResponseBody
    public String hello() {
        return "Hello";
    }


    @GetMapping("/err")
    @ResponseBody
    public String err() {
        return RestBean.failure().asJsonString();
    }
}
