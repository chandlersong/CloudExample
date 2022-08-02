package me.chandlersong.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth" )
@Data
public class AuthProperties {
    private boolean localServer;
    private long accessTokenValidity;
    private long refreshTokenValidity;
    private String issuerUri = "http://127.0.0.1:8080";
    private String clientId = "client";
    private String clientSecret = "{noop}secret";
    private String redirectUri = "https://oidcdebugger.com/debug";
    ;
}
