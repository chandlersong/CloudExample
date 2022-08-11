package me.chandlersong.helloworld;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Log4j2
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


    @Bean
    @Profile("default")
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        log.info("start default security configuration");
        http.csrf().disable().
            authorizeRequests(authz -> authz
                    .anyRequest().authenticated())
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    @Profile("mesh")
    SecurityFilterChain SecurityFilterChainForMesh(HttpSecurity http) throws Exception {
        log.info("start mesh security configuration");
        http.csrf().disable()
            .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll())
            .formLogin(form -> form.loginPage("/mylogin" ).permitAll());
        return http.build();
    }
}
