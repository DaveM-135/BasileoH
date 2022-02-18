package com.sophi.app.models.service;

import com.sophi.app.models.entity.Usuario;

public interface IUsuarioService {
	
	Usuario findByDescUsuario(String descUsuario);
	
	Usuario findByDescContrasenaAndDescUsuario(String descContrasena, String descUsuario); 
	
	void save(Usuario usuario);

}
