package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RecursoCapacitacion;

public interface IRecursoCapacitacionService {
	
	public List<RecursoCapacitacion> findByCodRecurso(Long codRecursoCapacitacion);
	
	public void save(RecursoCapacitacion recursoCapacitacion);
	
	public void delete(Long codRecursoCapaciacion);
	
	public RecursoCapacitacion findById(Long codRecursoCapacitacion);
	
	public Long countByCodCapacitacion(Long codCapacitacion);

}
