package me.chandlersong.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class WebSecurityConfig {
    // @formatter:off
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .and().authorizeRequests(authorizeRequests ->
                                             authorizeRequests.anyRequest().authenticated()
            )
            .formLogin(form -> form
                    .loginPage("/mylogin" )
                    .permitAll());
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
