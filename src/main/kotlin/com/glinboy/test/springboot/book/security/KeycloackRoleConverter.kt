package com.glinboy.test.springboot.book.security

import org.slf4j.LoggerFactory
import org.springframework.core.convert.converter.Converter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt

class KeycloackRoleConverter: Converter<Jwt, Collection<GrantedAuthority>> {
    private val logger = LoggerFactory.getLogger(javaClass)
    override fun convert(source: Jwt): Collection<GrantedAuthority> {
        val realAccess: Map<String, Object> = source.claims.get("realm_access") as Map<String, Object>
        if (realAccess == null || realAccess.isEmpty())
            return emptyList()
        val returnVal: Collection<GrantedAuthority> = (realAccess.get("roles") as List<String>)
            .map { "ROLE_" + it.uppercase() }
            .map { SimpleGrantedAuthority(it) }
            .toList()
        logger.info("User roles: ${returnVal}")
        return returnVal
    }
}
