package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.DetalleForecast;
import com.sophi.app.models.entity.MesHabil;
import com.sophi.app.models.entity.Proyecto;
import com.sophi.app.models.entity.Recurso;

public interface IDetalleForecastService {
	
	public List<DetalleForecast> findByRecurso(Recurso recurso);
	
	public List<DetalleForecast> findByRecursoAndProyecto(Recurso recurso, Proyecto proyecto);
	
	public List<DetalleForecast> findByRecursoAndMesHabil(Recurso recurso, MesHabil mesHabil);
	
	public void save(DetalleForecast detalleForecast);
	
	public void delete(Long codDetalleForecast);
	
	public DetalleForecast findById(Long codForecast);

}
