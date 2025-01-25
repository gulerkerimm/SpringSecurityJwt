package com.tpe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    //tokenı filtreleyeceğiz, requestden tokenı almamız gerekiyor.
    private String parseToken(HttpServletRequest request){

        String header=request.getHeader("Authorization");//Bearer eyTGGHYJUJHUK
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")){
            return header.substring(7);
        }
        return null;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //requestin içinden tokenı alalım
        String token=parseToken(request);

        try {
            if (token!=null && jwtUtils.validateToken(token)){
                //kullanıcı login olabilir:usernameni alalım
                String username=jwtUtils.getUsernameFromToken(token);
                //username ile userı bulabiliriz:login olan securitynin data tipinde user
                UserDetails user =userDetailsService.loadUserByUsername(username);

         /* Spring Security, kimlik doğrulama işleminden sonra kullanıcının
          bilgilerini Security Context'e otomatik olarak ekler. Ancak
          özel bir Filter yazılırsa, kimlik doğrulama sonrası Security Context'e
         kullanıcıyı manuel olarak eklemek gerekir.
         */

                //login olan userı security contexte koymak için authenticaion objesi gerekli
                UsernamePasswordAuthenticationToken authenticated=
                        new UsernamePasswordAuthenticationToken(user,
                                null,//password
                                user.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticated);

            }
        }catch (UsernameNotFoundException e){
            e.getStackTrace();
        }

        filterChain.doFilter(request,response);
        //bu filtreden sonra diğer filtreler ile devam et


    }
}