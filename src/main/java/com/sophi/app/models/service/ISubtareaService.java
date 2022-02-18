package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Subtarea;

public interface ISubtareaService {
	
	public List<Subtarea> findAll();
	
	public Subtarea findOne(Long codSubtarea);
	
	public List<Subtarea> findByCodTarea(Long codTarea);
	
	public List<Subtarea> findFueraDePlan();

}
