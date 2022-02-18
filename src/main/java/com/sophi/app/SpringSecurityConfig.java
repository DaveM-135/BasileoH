package com.sophi.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.sophi.app.models.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{
	
	 @Autowired
	 private JpaUserDetailsService userDetailsService;
	 
	 @Autowired
	 private BCryptPasswordEncoder passwordEncoder;
		
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/css/**","/js/**","/img/**","/scss/**","/vendor/**","/sendingEmail","/resetPassword","/newPassword**","/registroWebinar**","/fotoRecursoPerfil/**").permitAll()
//		.antMatchers("/**").hasAnyRole("USER")
//		.antMatchers("/listaClientes/**").hasAnyRole("ROLE_ADMIN","ROLE_LIDER")
//		.antMatchers("/agenda").hasAnyRole("ROLE_ADMIN","ROLE_LIDER")
//		.antMatchers("/listaProyectosTodo").hasAnyRole("ROLE_ADMIN")
//		.antMatchers("/listaMisProyectos/**").hasAnyRole("ROLE_LIDER")
//		.antMatchers("/misActividades/**").hasAnyRole("ROLE_LIDER","ROLE_USER")
//		.antMatchers("/aprobacionhoras/**").hasAnyRole("ROLE_LIDER","ROLE_ADMIN")
//		.antMatchers("/aprobaciongastos/**").hasAnyRole("ROLE_LIDER","ROLE_ADMIN")
		.anyRequest().authenticated()
		.and()
			.formLogin()
				.loginPage("/login")
			.permitAll()
		.and()
			.logout().permitAll()
		.and()
			.exceptionHandling().accessDeniedPage("/accessDenied");
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
