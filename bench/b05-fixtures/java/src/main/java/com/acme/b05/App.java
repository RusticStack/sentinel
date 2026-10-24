package com.acme.b05;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class App {
    @GetMapping("/")
    public String hello() {
        return "b05";
    }
}
