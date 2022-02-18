package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Jornada;

public interface IJornadaService {
	
	public List<Jornada> findAll();
	
	public Jornada findOne(Long codJornada);

}
