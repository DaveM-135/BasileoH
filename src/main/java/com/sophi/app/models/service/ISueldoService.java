package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Sueldo;

public interface ISueldoService {
	
	public List<Sueldo> findAll();
	
	public void save(Sueldo sueldo);
	
	public Sueldo findOne(Long codSueldo);
	
	public void delete(Sueldo sueldo);

}
