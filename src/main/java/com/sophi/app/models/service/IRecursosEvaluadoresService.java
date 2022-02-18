package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RecursoEvaluador;

public interface IRecursosEvaluadoresService {

	public void guardar(RecursoEvaluador recursoEvaluador);
	
	public void guardarAll(List<RecursoEvaluador> listRecursosEvaluadores);
	
	public RecursoEvaluador findById(Long codRecursoEvaluador);
	
	public List<RecursoEvaluador> findByCodEvaluacionDesempenoAndCodRecurso(Long codEvaluacionDesempeno, Long codRecurso);

	public List<RecursoEvaluador> findByCodEvaluacionDesempenoAndCodEvaluador(Long codEvaluacionDesempeno, Long codEvaluador);
	
	public void deleteById(Long codRecursoEvaluador);
	
	public List<RecursoEvaluador> findByCodEvaluacionDesempeno(Long codEvaluacionDesempeno);
	
	public void deleteRecursoEvaluadorByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacionDesempeno);
	
}
