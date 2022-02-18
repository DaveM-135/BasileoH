package com.sophi.app.models.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IUsuarioDao;
import com.sophi.app.models.entity.Rol;
import com.sophi.app.models.entity.Usuario;

@Service("JpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService{

	@Autowired
	private IUsuarioDao usuarioDao;
	
	private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);
	
	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Usuario usuario = usuarioDao.findByDescUsuario(username);
		
		if (usuario == null) {
			logger.error("Error login: no existe el usuario " + username);
			throw new UsernameNotFoundException("Usuario no existe el sistema");
		}
		
		List<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
		
		for (Rol rol : usuario.getRoles()) {
			logger.info("Rol:"+ rol.getDescRol());
			roles.add(new SimpleGrantedAuthority(rol.getDescRol()));
		}
		
		if (roles.isEmpty()) {
			logger.error("Error login:"+ username + " no tiene permisos");
			throw new UsernameNotFoundException("Usuario no tiene roles");
		}
		
		return new User(usuario.getDescUsuario(), usuario.getDescContrasena(), usuario.getDescActivo(), true, true, true, roles);
	}

}
