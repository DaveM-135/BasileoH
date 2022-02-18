package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Concepto;
import com.sophi.app.models.entity.DetalleEvaluacionProyecto;

public interface IDetalleEvaluacionProyectoDao extends CrudRepository<DetalleEvaluacionProyecto, Long>{
	
	
	public DetalleEvaluacionProyecto findByConceptoAndCodProyecto(Concepto concepto, Long codProyecto);
	
	public List<DetalleEvaluacionProyecto> findByCodProyecto(Long codProyecto);
	
	@Query("SELECT COUNT(*) FROM DetalleEvaluacionProyecto dep WHERE (dep.codEvaluacion IS NULL AND dep.calificacion = 0) AND dep.codProyecto = ?1 ")
	public Integer conceptosNoEvaluadosByCodProyecto(Long codProyecto);

}
