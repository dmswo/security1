package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// 1.코드받기(인증)
// 2.엑세스토큰(권한)
// 3.사용자프로필 정보를 가져옴
// 4-1.그 정보를 토대로 회원가입을 자동으로 진행
// 4-2.(이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소)
@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화, preAuthorize or PostAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                // 인증만 되면 들어갈 수 있는 주소!!
                .antMatchers("/user/**").authenticated()
                // manager 접근시 'ROLE_ADMIN', 'ROLE_MANAGER'권한이 있는 사람만 접근가능
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                // admin 'ROLE_ADMIN' 권한이 있는 사람만 접근가능
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 나머지는 다 접근가능
                .anyRequest().permitAll()
                // 권한이 없는페이지로 요청이 들어올때 로그인페이지로 이동(3줄)
                .and()
                .formLogin()
                .loginPage("/loginForm")
                // /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                .loginProcessingUrl("/login")
                // login 완료되면 "/"호출해줄건데 특정페이지로 접근시 로그인을 하게 될 경우 다시 그 페이지로 보내줌(ex:admin -> loginForm -> admin)
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService); // 구글 로그인이 완료된 뒤에 후처리가 필요함.
    }
}
