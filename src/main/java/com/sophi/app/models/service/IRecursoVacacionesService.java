package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RecursoVacaciones;

public interface IRecursoVacacionesService {
	
	public RecursoVacaciones findById(Long codRecursoVacaciones);
	
	public List<RecursoVacaciones> findAll();
	
	public void save(RecursoVacaciones recursoVacaciones);
	
}
