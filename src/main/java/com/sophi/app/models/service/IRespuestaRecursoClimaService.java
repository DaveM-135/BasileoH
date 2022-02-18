package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RespuestaRecursoClima;

public interface IRespuestaRecursoClimaService {
	
	public List<RespuestaRecursoClima> findAll();
	
	public RespuestaRecursoClima findOne(Long codRespuestaRecursoClima);
	
	public void save(RespuestaRecursoClima respuestaRecursoClima);
	
	public void delete(Long codRespuestaRecursoClima);
	
	public List<RespuestaRecursoClima> findByRecurso(Recurso recurso);

}
