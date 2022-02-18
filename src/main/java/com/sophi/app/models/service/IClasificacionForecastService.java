package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.ClasificacionForecast;

public interface IClasificacionForecastService {
	
	public List<ClasificacionForecast> findAll();
	
	public ClasificacionForecast findByCodClasificacion(Long codClasificacion);
	
	List<String> findUniqueDescClasificacionPresupuesto();
	
	List<ClasificacionForecast> findByDescClasificacionPresupuesto(String descClasificacionPresupuesto);

}
