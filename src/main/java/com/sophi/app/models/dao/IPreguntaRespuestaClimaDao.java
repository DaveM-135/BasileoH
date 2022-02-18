package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.PreguntaRespuestaClima;

public interface IPreguntaRespuestaClimaDao extends CrudRepository<PreguntaRespuestaClima, Long>{
	
	public List<PreguntaRespuestaClima> findByPreguntaClimaCodPreguntaClima(Long codPregunta);

}
