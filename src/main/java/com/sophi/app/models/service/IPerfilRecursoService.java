package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.PerfilRecurso;

public interface IPerfilRecursoService {
	
	public PerfilRecurso findByCodPerfil(Long codPerfil);
	
	public List<PerfilRecurso> findAll();
	
	public void guardar(PerfilRecurso perfil);
	
	public Long totalRecursosAsignados(Long codPerfil);
	
	public void borrar(Long codPerfil);

	public void guardarAll(List<PerfilRecurso> perfiles);
}
