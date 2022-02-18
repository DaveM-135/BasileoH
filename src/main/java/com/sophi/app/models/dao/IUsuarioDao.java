package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Usuario;

public interface IUsuarioDao extends CrudRepository<Usuario, Long>{

	Usuario findByDescUsuario(String descUsuario);
	
	Usuario findByDescContrasenaAndDescUsuario(String descContrasena, String descUsuario);
	
	
}
