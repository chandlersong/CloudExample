package me.chandlersong.jwt;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Log4j2
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfig {
    // @formatter:off
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        log.info("start default security configuration");
        http.csrf().disable().authorizeRequests()
            .antMatchers("/login/**" ).permitAll()
            .and().authorizeRequests(authorizeRequests ->
                                             authorizeRequests.anyRequest().authenticated()
            ).formLogin(form -> form
                    .loginPage("/mylogin" )
                    .permitAll());
        return http.build();
    }
    // @formatter:on


    @Bean
    @Profile("mesh")
    SecurityFilterChain SecurityFilterChainForMesh(HttpSecurity http) throws Exception {
        log.info("start mesh security configuration");
        http.csrf().disable()
            .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll())
            .formLogin(form -> form.loginPage("/mylogin" ).permitAll());
        return http.build();
    }
    // @formatter:on

    // @formatter:off
    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                               .username("user" )
                               .password("password" )
                               .roles("USER" )
                               .build();
        return new InMemoryUserDetailsManager(user);
    }
    // @formatter:on
}
