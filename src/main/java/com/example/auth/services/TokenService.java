package com.example.auth.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
public class TokenService {
    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;
      public String generateJwtToken(Authentication auth){
          String scope= auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
          JwtClaimsSet claimSet= JwtClaimsSet.builder().issuer("self").issuedAt(Instant.now()).subject(auth.getName()).claim("roles",scope).build();
          return jwtEncoder.encode(JwtEncoderParameters.from(claimSet)).getTokenValue();
      }
}
