package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Puesto;


public interface IPuestoService {
	
	public List<Puesto> findAll();
	
	public Puesto findOne(Long codPuesto);

}
