package me.chandlersong.helloworld;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RestController
public class HelloWorldController {

    @GetMapping("/hello")
    public Res sayHello(@RequestParam String name) {
        log.info("receive request,name is {}", name);
        return new Res("hello " + name);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    class Res {
        private String name;
    }
}
