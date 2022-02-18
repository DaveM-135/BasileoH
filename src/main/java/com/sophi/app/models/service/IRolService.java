package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Rol;

public interface IRolService {
	
	public List<Rol> findListaRoles();
	
	public List<Rol> findByCodRecurso(Long codRecurso);
	
	public List<String> getListaAdminRh();

}
