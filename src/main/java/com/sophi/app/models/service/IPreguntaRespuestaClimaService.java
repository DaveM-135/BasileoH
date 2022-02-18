package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.PreguntaRespuestaClima;

public interface IPreguntaRespuestaClimaService {
	
	public List<PreguntaRespuestaClima> findAll();
	
	public PreguntaRespuestaClima findOne(Long codPreguntaRespuestaClima);
	
	public List<PreguntaRespuestaClima> findByCodPregunta(Long codPregunta);
	
	public void save(PreguntaRespuestaClima preguntaRespuestaClima);
	
	public void delete(Long codPreguntaRespuestaClima);


}
