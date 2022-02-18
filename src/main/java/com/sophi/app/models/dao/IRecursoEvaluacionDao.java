package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.RecursoEvaluacion;

public interface IRecursoEvaluacionDao extends CrudRepository<RecursoEvaluacion, Long>{
	
	public List<RecursoEvaluacion> findByCodEvaluacionDesempeno(Long codEvaluacionDesempeno);
	
	public List<RecursoEvaluacion> findByCodRecurso(Long codRecurso);
	
	public List<RecursoEvaluacion> findByCodRecursoAndValTipoEvaluador(Long codRecurso, Long valTipoEvaluador);
	
	public RecursoEvaluacion findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluadorAndValTipoEvaluador(Long codRecurso,Long codEvaluacionDesempeno,Long codRecursoEvaluador,Long valTipoEvaluador);
	
	public List<RecursoEvaluacion> findByCodRecursoEvaluadorAndValTipoEvaluador(Long codRecursoEvaluador, Long valTipoEvaluador);
	
	@Query(value="SELECT CAST(ROUND(AVG(val_resultado_competencias),2) AS DEC(10,2)) as promedioCompetencias FROM RECURSOS_EVALUACIONES where cod_recurso = ?1 and cod_evaluacion_desempeno = ?2", nativeQuery = true)
	public Float getPromedioCompetenciasByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion);
	
	@Query(value="SELECT CAST(ROUND(AVG(val_resultado_competencias),2) AS DEC(10,2)) as promedioCompetencias FROM RECURSOS_EVALUACIONES where cod_recurso = ?1 and cod_evaluacion_desempeno = ?2 and val_tipo_evaluador = ?3", nativeQuery = true)
	public Float getPromedioCompetenciasByCodRecursoAndCodEvaluacionAndTipo(Long codRecurso, Long codEvaluacion, Long Tipo);
	
	public List<RecursoEvaluacion> findByCodRecursoAndCodEvaluacionDesempeno(Long codRecurso,Long codEvaluacionDesempeno);
	
	@Query(value="SELECT CAST(ROUND(AVG(val_resultado_competencias),2) AS DEC(10,2)) as promedioCompetencias FROM RECURSOS_EVALUACIONES where cod_evaluacion_desempeno = ?1", nativeQuery = true)
	public Float getPromedioCompetenciasByCodEvaluacion(Long codEvaluacion);

}
