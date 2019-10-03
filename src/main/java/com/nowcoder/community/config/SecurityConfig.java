package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略ant风格路径下的资源，即忽略resources目录下所有的资源
        // 忽略静态资源的访问
        web.ignoring().antMatchers("/resources/**");
    }

    // 配置认证
    // AuthenticationManager：认证的核心接口
    // AuthenticationManagerBuilder：用于构建AuthenticationManager对象的工具
    // ProviderManager：AuthenticationManager接口的默认实现类
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内置的认证规则
        // Pbkdf2PasswordEncoder：密码加密工具，其参数为salt，salt和原始密码一起加密
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));


        // 自定义认证规则
        // AuthenticationProvider：ProviderManager持有一组AuthenticationProvider，每个AuthenticationProvider负责一种认证
        // 委托模式：ProviderManager将认证委托给AuthenticationProvider

        // 实例化一个账号密码认证
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication：用于封装认证信息的接口，不同的实现类代表不同类型的认证信息
            // authenticate方法里面写认证的逻辑
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();

                User user = userService.findUserByName(username);

                if (user == null) {
                    throw new UsernameNotFoundException("账号不存在！");
                }

                password = CommunityUtil.md5(password + user.getSalt());
                if (!user.getPassword().equals(password)) {
                    throw new BadCredentialsException("密码不正确！");
                }

                // principal：认证的主要信息，一般我们存user
                // credentials：证书，账号密码模式下也就是密码
                // authorities：权限
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            // 当前AuthenticationProvider支持哪种类型的认证
            @Override
            public boolean supports(Class<?> aClass) {
                // UsernamePasswordAuthenticationToken：Authentication接口的常用的一个实现类，账号密码认证
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登录相关配置
        http.formLogin()
                // 登录页面
                .loginPage("/loginpage")
                // 登录的处理路径
                .loginProcessingUrl("/login")
                // 登录成功时的处理器
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // 成功时重定向到首页
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                })
                // 失败时的处理器
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        request.setAttribute("error", e.getMessage());
                        // 将请求转发到登录页面
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                    }
                });

        // 退出相关配置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                });

        // 授权配置
        // 配置哪些页面需要哪些权限
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")
                .and().exceptionHandling().accessDeniedPage("/denied");

        // 增加Filter，处理验证码
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest) servletRequest;
                HttpServletResponse response = (HttpServletResponse) servletResponse;

                // 如果当前的请求路径是登录验证的话
                if (request.getServletPath().equals("/login")) {
                    String verifyCode = request.getParameter("verifyCode");
                    // 如果验证码为空，或者不正确
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")) {
                        request.setAttribute("error", "验证码错误！");
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                        return;
                    }
                }
                // 否则的话，让请求继续向下执行
                filterChain.doFilter(request, response);
            }
        }, UsernamePasswordAuthenticationFilter.class);

        // 处理记住我
        http.rememberMe()
                // 存储用户数据的方案
                .tokenRepository(new InMemoryTokenRepositoryImpl())
                // 过期时间
                .tokenValiditySeconds(3600 * 24)
                .userDetailsService(userService);

    }
}
