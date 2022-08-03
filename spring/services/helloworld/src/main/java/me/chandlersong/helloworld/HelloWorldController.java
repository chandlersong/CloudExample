package me.chandlersong.helloworld;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

    @GetMapping("/hello")
    public Res sayHello(@RequestParam String name) {
        return new Res("hello " + name);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    class Res {
        private String name;
    }
}
