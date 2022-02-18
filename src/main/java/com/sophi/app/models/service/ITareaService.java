package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Tarea;

public interface ITareaService {
	
	public List<Tarea> findAll();
	
	public Tarea findOne(Long codTarea);
	
	public List<Tarea> findTareaFueraPlan();

}
