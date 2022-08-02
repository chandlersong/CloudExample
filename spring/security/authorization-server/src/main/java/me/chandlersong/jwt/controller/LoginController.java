package me.chandlersong.jwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/mylogin" )
    String login(Model model) {

        return "mylogin";
    }


    @GetMapping("/" )
    String hello(Model model) {

        return "helloworld";
    }

}
