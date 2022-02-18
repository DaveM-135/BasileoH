package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.ClasificacionForecast;

public interface IClasificacionForecastDao extends CrudRepository<ClasificacionForecast, Long>{

	@Query("FROM ClasificacionForecast C WHERE C.valForecast = 1")
	List<ClasificacionForecast> findAll();
	
	
	@Query("SELECT distinct(C.descClasificacion) FROM ClasificacionForecast C WHERE C.valForecast = 1 order by C.descClasificacion asc")
	List<String> findUniqueDescClasificacionPresupuesto();
	
	@Query("FROM ClasificacionForecast C WHERE C.valForecast = 1 and C.descClasificacion = ?1 order by C.descClasificacionPresupuesto asc")
	List<ClasificacionForecast> findByDescClasificacionPresupuesto(String descClasificacionPresupuesto);
	
}
