package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Dependiente;

public interface IDependienteService {
	
	public List<Dependiente> findAll();
	
	public void save(Dependiente dependiente);
	
	public Dependiente findOne(Long codDependiente);
	
	public void delete(Dependiente dependiente);

}
