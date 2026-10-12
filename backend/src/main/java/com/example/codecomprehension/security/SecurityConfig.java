package com.example.codecomprehension.security;
import com.example.codecomprehension.auth.*;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.cors.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.*;
@Configuration
public class SecurityConfig {
 @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder(12);}
 @Bean SecurityFilterChain security(HttpSecurity http,AuthService service,@Value("${app.auth.allowed-origins}") String origins)throws Exception {
  CorsConfiguration cors=new CorsConfiguration();cors.setAllowedOrigins(Arrays.asList(origins.split(",")));cors.setAllowedMethods(List.of("GET","POST","OPTIONS"));cors.setAllowedHeaders(List.of("Authorization","Content-Type"));
  UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();source.registerCorsConfiguration("/api/**",cors);
  http.cors(c->c.configurationSource(source)).csrf(c->c.disable()).sessionManagement(c->c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .formLogin(c->c.disable()).httpBasic(c->c.disable()).logout(c->c.disable()).requestCache(c->c.disable())
   .authorizeHttpRequests(c->c.requestMatchers(org.springframework.http.HttpMethod.POST,"/api/auth/register","/api/auth/login","/api/auth/forgot-password","/api/auth/reset-password").permitAll().requestMatchers(org.springframework.http.HttpMethod.GET,"/api/auth/verify-email","/api/auth/reset-password").permitAll().requestMatchers("/api/admin/**").hasRole("ADMIN").anyRequest().authenticated())
   .exceptionHandling(c->c.authenticationEntryPoint((req,res,ex)->error(res,401,"Требуется авторизация")).accessDeniedHandler((req,res,ex)->error(res,403,"Недостаточно прав")))
   .addFilterBefore(new OncePerRequestFilter(){
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException {
     String header=req.getHeader("Authorization");
     if(header!=null && header.startsWith("Bearer ") && header.length()<=135){
      service.authenticate(header.substring(7)).ifPresent(u->SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(u,null,List.of(new SimpleGrantedAuthority("ROLE_"+u.role())))));
     }
     chain.doFilter(req,res);
    }
   },UsernamePasswordAuthenticationFilter.class);
  return http.build();
 }
 private static void error(HttpServletResponse res,int status,String message)throws IOException{res.setStatus(status);res.setContentType("application/json;charset=UTF-8");res.getWriter().write("{\"message\":\""+message+"\"}");}
 @Bean ApplicationRunner admin(AuthService service,@Value("${app.auth.admin-email}")String email,@Value("${app.auth.admin-password}")String password){return args->{
  if(email.isBlank() && password.isBlank())return;
  if(!email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+") || password.length()<8 || password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>72)throw new IllegalArgumentException("ADMIN_EMAIL и ADMIN_PASSWORD должны быть корректны (пароль 8–72 байта)");
  service.bootstrap(email,password);
 };}
}
