package me.chandlersong.jwt.controller;

import lombok.extern.slf4j.Slf4j;
import me.chandlersong.jwt.domain.LoginInfo;
import me.chandlersong.jwt.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

@Slf4j
@RestController
public class Oauth2LoginController {

    @Autowired
    private LoginService authService;


    @PostMapping(path = "/login/password", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getUserTokenInfo(
            @RequestBody LoginInfo loginInfo) {
        return authService.getAccessTokenForRequest(loginInfo);
    }


}
