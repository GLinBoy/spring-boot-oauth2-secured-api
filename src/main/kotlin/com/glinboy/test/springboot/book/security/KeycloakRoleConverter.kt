package com.glinboy.test.springboot.book.security

import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt

class KeycloakRoleConverter : Converter<Jwt, Collection<GrantedAuthority>> {

    override fun convert(source: Jwt): Collection<GrantedAuthority> =
        (source.claims["realm_access"] as Map<String, List<String>>).let {
            it["roles"].let {
                it?.map { "ROLE_" + it.uppercase() }
                    ?.map { SimpleGrantedAuthority(it) }
                    ?.toList()
            }
        } ?: emptyList()

}
