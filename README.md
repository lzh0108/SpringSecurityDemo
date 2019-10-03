# SpringSecurityDemo

## 使用Spring Security的大致步骤
1. 导入pom依赖
2. 配置实体类，实体类继承UserDetails接口，并实现其多个方法进行配置<br/>
isAccountNonExpired()，isAccountNonLocked()，isCredentialsNonExpired()，isEnabled()，getAuthorities()
3. 在业务层配置UserService，实现UserDetailsService接口，并实现loadUserByUsername()，使得SpringSecurity能够根据用户名查询用户
4. 编写配置类SecurityConfig，继承WebSecurityConfigurerAdapter类：<br/>
configure(WebSecurity web) 配置SpringSecuriy的权限控制范围<br/>
configure(AuthenticationManagerBuilder auth) 配置认证<br/>
configure(HttpSecurity http) 配置授权<br/>

具体实现请了解代码示例
