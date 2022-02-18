package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RecursoGasto;

public interface IRecursoGastoService {
	
	public List<RecursoGasto> findAll();
	
	public void save(RecursoGasto recursoGasto);
	
	public RecursoGasto findOne(Long recursoGasto);
	
	public void delete(RecursoGasto recursoGasto);
	
	public List<RecursoGasto> findByCodRecurso(Long codRecurso);
	
}
