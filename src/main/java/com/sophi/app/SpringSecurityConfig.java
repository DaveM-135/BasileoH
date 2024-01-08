package com.sophi.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.sophi.app.models.service.JpaUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SpringSecurityConfig {
	
	 @Autowired
	 private JpaUserDetailsService userDetailsService;
	 
	 @Autowired
	 private BCryptPasswordEncoder passwordEncoder;
		
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
		.authorizeHttpRequests(authorizeHttpRequests -> 
			authorizeHttpRequests.antMatchers("/css/**","/js/**","/img/**","/scss/**","/vendor/**","/sendingEmail","/resetPassword","/newPassword**","/registroWebinar**","/fotoRecursoPerfil/**").permitAll()
			.anyRequest().authenticated()
		)
		.httpBasic(Customizer.withDefaults())
		.sessionManagement(sess->sess.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
		.formLogin(formLogin ->
			formLogin.loginPage("/login").permitAll()
		)
		.logout(logout -> logout.permitAll())
		.exceptionHandling(exception -> 
			exception.accessDeniedPage("/accessDenied")
		);

		return http.build();
	}


	
	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {
		builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
//		String[ ] pass = {"QZA3zk4P","cNV5WFjB"};
//		for (String p : pass) {
//			System.out.println(p + " - " + passwordEncoder.encode(p));
//		}
	}
	
}
