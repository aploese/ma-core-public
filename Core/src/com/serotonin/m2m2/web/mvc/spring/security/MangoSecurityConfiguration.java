/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.spring.security;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.serotonin.m2m2.Common;
import com.serotonin.m2m2.web.mvc.spring.authentication.MangoUserAuthenticationProvider;
import com.serotonin.m2m2.web.mvc.spring.authentication.MangoUserDetailsService;
import com.serotonin.m2m2.web.mvc.spring.components.JwtService;

/**
 * Spring Security Setup for REST based requests 
 * 
 * @author Terry Packer
 *
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class MangoSecurityConfiguration {

    @Autowired
    public void configureAuthenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).and()
            .authenticationProvider(authenticationProvider());
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        return new MangoUserDetailsService();
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new MangoUserAuthenticationProvider();
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
          HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
          repository.setHeaderName("X-XSRF-TOKEN");
          return repository;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new MangoAccessDeniedHandler();
    }
    
    // shouldn't be needed if we switch to formLogin() configuration
    /*@Bean AuthenticationEntryPoint authenticationEntryPoint() {
        return new LoginUrlAuthenticationEntryPoint("/login.htm");
    }*/
    
    @Bean
    public CsrfHeaderFilter csrfHeaderFilter() {
        return new CsrfHeaderFilter();
    }

    @Configuration
    @Order(1)
    public static class RestSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Autowired JwtService jwtService;
        @Autowired CsrfTokenRepository csrfTokenRepository;
        @Autowired CsrfHeaderFilter csrfHeaderFilter;
        
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/rest/**")
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                    .and()
                .formLogin().disable()
                .logout().disable()
                .rememberMe().disable()
                .authorizeRequests()
                    .antMatchers("/rest/v1/login/**").permitAll()
                    .antMatchers(HttpMethod.GET, "/rest/v1/translations/public/**").permitAll() //For public translations
                    .antMatchers(HttpMethod.POST, "/rest/v1/jwt/login").permitAll()
                    .antMatchers(HttpMethod.OPTIONS).permitAll()
                    .anyRequest().authenticated()
                    .and()
                //CSRF Headers https://spring.io/blog/2015/01/12/the-login-page-angular-js-and-spring-security-part-ii
                .addFilterAfter(csrfHeaderFilter, CsrfFilter.class)
                .csrf()
                    .csrfTokenRepository(csrfTokenRepository)
                    .ignoringAntMatchers("/rest/v1/jwt/login")
                    .requireCsrfProtectionMatcher(new RequestMatcher() {
                        // extended version of org.springframework.security.web.csrf.CsrfFilter.DefaultRequiresCsrfMatcher
                        // does not apply CSRF protection if the user is authenticated via a JWT token
                        private Pattern allowedMethods = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

                        public boolean matches(HttpServletRequest request) {
                            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                            if (auth != null && auth instanceof PreAuthenticatedAuthenticationToken) {
                                return false;
                            }
                            return !allowedMethods.matcher(request.getMethod()).matches();
                        }
                    })
                    .and()
                .headers()
                    .frameOptions().sameOrigin()
                    .and()
                .exceptionHandling()
                    .and()
                .addFilterBefore(new AuthenticationTokenFilter(jwtService), BasicAuthenticationFilter.class);
        }
    }
    
    @Configuration
    @Order(2)
    public static class DefaultSecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Autowired CsrfTokenRepository csrfTokenRepository;
        @Autowired AccessDeniedHandler accessDeniedHandler;
        //@Autowired AuthenticationEntryPoint authenticationEntryPoint;
        @Autowired CsrfHeaderFilter csrfHeaderFilter;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
            .formLogin()
                .permitAll()
                .and()
            .logout()
                .invalidateHttpSession(true)
                .deleteCookies("XSRF-TOKEN","MANGO" + Common.envProps.getInt("web.port", 8080))
                .and()
            .rememberMe()
                .and()
            .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/login.htm").permitAll()
                .antMatchers(HttpMethod.POST, "/login.htm").permitAll()
                // allow public access to resources folder
                .antMatchers(HttpMethod.GET, "/resources/**").permitAll()
                .antMatchers(HttpMethod.GET, "/" + Common.getVersion() + "/resources/**").permitAll()
                // allow public access to GET DWR .js files
                .antMatchers(HttpMethod.GET, "/dwr/**/*.js").permitAll()
                .antMatchers(HttpMethod.GET, "/" + Common.getVersion() + "/dwr/**/*.js").permitAll()
                .antMatchers(HttpMethod.GET, "/images/**").permitAll()
                .antMatchers(HttpMethod.GET, "/audio/**").permitAll()
                .antMatchers(HttpMethod.GET, "/swagger/**").permitAll()
                .antMatchers(HttpMethod.GET, "/exception/*").permitAll()
                // Allow Startup REST Endpoint
                .antMatchers(HttpMethod.GET, "/status/*").permitAll()
                // OPTIONS should be allowed on all
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                // dont allow access to any modules folders other than web
                .antMatchers(HttpMethod.GET, "/modules/*/web/**").permitAll()
                .antMatchers(HttpMethod.GET, "/" + Common.getVersion() + "/modules/*/web/**").permitAll()
                .antMatchers("/modules/**").denyAll()
                .antMatchers("/" + Common.getVersion() + "/modules/**").denyAll()
                // Access to *.shtm files must be authenticated
                .antMatchers("/**/*.shtm").authenticated()
                // allow access to items in root directory but not subdirectories
                .antMatchers("/*").permitAll()
                .anyRequest().authenticated()
                .and()
            //CSRF Headers https://spring.io/blog/2015/01/12/the-login-page-angular-js-and-spring-security-part-ii
            .addFilterAfter(csrfHeaderFilter, CsrfFilter.class)
            .csrf()
                // TODO check that DWR handles its own CRSF protection
                .ignoringAntMatchers("/dwr/**", "/" + Common.getVersion() + "/dwr/**")
                .csrfTokenRepository(csrfTokenRepository)
                .and()
            .exceptionHandling()
                //.authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
                .and()
            //Customize the headers here
            .headers()
                .frameOptions().sameOrigin();
        }
    }
}
