package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.PreguntaClima;

public interface IPreguntaClimaService {
	
	public List<PreguntaClima> findAll();
	
	public PreguntaClima findOne(Long codPreguntaClima);
	
	public void save(PreguntaClima preguntaClima);
	
	public void delete(Long codPreguntaClima);

}
