package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RespuestaRecursoClima;

public interface IRespuestaRecursoClimaDao extends CrudRepository<RespuestaRecursoClima, Long>{
	
	public List<RespuestaRecursoClima> findByRecurso(Recurso recurso); 

}
