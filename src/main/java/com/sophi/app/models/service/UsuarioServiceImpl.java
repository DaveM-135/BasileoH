package com.sophi.app.models.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IUsuarioDao;
import com.sophi.app.models.entity.Usuario;

@Service
public class UsuarioServiceImpl implements IUsuarioService{
	
	@Autowired
	private IUsuarioDao usuarioDao;

	@Override
	@Transactional(readOnly = true)
	public Usuario findByDescUsuario(String descUsuario) {
		return usuarioDao.findByDescUsuario(descUsuario);
	}

	@Override
	@Transactional(readOnly = true)
	public Usuario findByDescContrasenaAndDescUsuario(String descContrasena, String descUsuario) {
		return usuarioDao.findByDescContrasenaAndDescUsuario(descContrasena, descUsuario);
	}

	@Override
	@Transactional
	public void save(Usuario usuario) {
		usuarioDao.save(usuario);
	}

}
