package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.DetalleForecast;
import com.sophi.app.models.entity.MesHabil;
import com.sophi.app.models.entity.Proyecto;
import com.sophi.app.models.entity.Recurso;

public interface IDetalleForecastDao extends CrudRepository<DetalleForecast, Long>{
	
	public List<DetalleForecast> findByRecurso(Recurso recurso);
	
	public List<DetalleForecast> findByRecursoAndProyecto(Recurso recurso, Proyecto proyecto);
	
	public List<DetalleForecast> findByRecursoAndMesHabil(Recurso recurso, MesHabil mesHabil);
	

}
