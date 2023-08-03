package com.glinboy.test.springboot.book.config

import com.glinboy.test.springboot.book.security.KeycloackRoleConverter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

@Configuration
@EnableWebSecurity
class SecurityConfig {

    private val AUTH_WHITELIST = arrayOf(
        "/",
        "/swagger-ui.html",
        "/v3/api-docs/**",
        "/swagger-ui/**",
        // other public endpoints of your API may be appended to this array
        "/h2-console/**"
    )

    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        val jwtAuthenticationConverter = JwtAuthenticationConverter()
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(KeycloackRoleConverter())
        return http
            .cors { it.disable() }
            .csrf { it.disable() }
            .headers { it.frameOptions { it.disable() } }
            .authorizeHttpRequests {
                it
                    .requestMatchers(
                        *AUTH_WHITELIST.map { AntPathRequestMatcher(it) }.toTypedArray()
                    ).permitAll()
                    .requestMatchers(AntPathRequestMatcher("/api/v1/users")).hasAnyRole("ADMIN")
                    .anyRequest().authenticated()
            }
            .oauth2ResourceServer {
                it.jwt { it.jwtAuthenticationConverter(jwtAuthenticationConverter) }
            }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .build()
    }
}
