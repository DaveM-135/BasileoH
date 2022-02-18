package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Concepto;
import com.sophi.app.models.entity.DetalleEvaluacionProyecto;

public interface IDetalleEvaluacionProyectoService {
	
	public void guardarDetalle(DetalleEvaluacionProyecto  detalleEvaluacionProyecto);
	
	public void guardarTodosDetalle(List<DetalleEvaluacionProyecto>  detallesEvaluacionProyecto);
	
	public DetalleEvaluacionProyecto findById(Long codDetalleEvaluacion);
	
	public DetalleEvaluacionProyecto findByConceptoAndCodProyecto(Concepto concepto, Long codProyecto);
	
	public List<DetalleEvaluacionProyecto> findByCodProyecto(Long codProyecto);
	
	public void eliminarDetalle(Long codDetalle);
	
	public Integer conceptosNoEvaluadosByCodProyecto(Long codProyecto);
	

}
