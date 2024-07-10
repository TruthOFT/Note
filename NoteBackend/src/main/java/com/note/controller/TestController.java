package com.note.controller;

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
}
