package com.example.auth.controllers;

import com.example.auth.controllers.dto.UserDetailsDto;
import com.example.auth.services.TokenService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class DemoController {
    @Autowired
    private TokenService tokenService;
    @Autowired
    private JwtEncoder jwtEncoder;
    @GetMapping("/sai")
    public String getDemo(){
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getDetails());
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());

        return "demo";
    }
    @GetMapping("/ram")
    public String getDemo2() {

        System.out.println(SecurityContextHolder.getContext().getAuthentication().getDetails());
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());


        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "sairam  "+tokenService.generateJwtToken(auth);
//        String scope= auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
//        JwtClaimsSet claimSet= JwtClaimsSet.builder().issuer("self").issuedAt(Instant.now()).subject(auth.getName()).claim("roles",scope).build();
//        return jwtEncoder.encode(JwtEncoderParameters.from(claimSet)).getTokenValue();




//        return rsaPublicKey.toString()+SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString();
    }
    @GetMapping("/sairam")
    public String getDemo3(){
        return "sairam";
    }


}
