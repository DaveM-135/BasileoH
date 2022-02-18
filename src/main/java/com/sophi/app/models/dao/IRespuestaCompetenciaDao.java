package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.RespuestaCompetencia;

public interface IRespuestaCompetenciaDao extends CrudRepository<RespuestaCompetencia, Long> {

	public List<RespuestaCompetencia> findByCodRecursoAndCodEvaluacionDesempenoAndValTipoEvaluadorOrderByCodCompetencias(Long codRecurso, Long codEvaluacionDesempeno, Long valTipo);
	
	public List<RespuestaCompetencia> findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluadorOrderByCodCompetencias(Long codRecurso, Long codEvaluacionDesempeno, Long codRecursoEvaluador);
	
	public List<RespuestaCompetencia> findByCodRecursoAndCodEvaluacionDesempenoAndValTipoEvaluadorAndCodRecursoEvaluadorOrderByCodCompetencias(Long codRecurso, Long codEvaluacionDesempeno, Long valTipo, Long codRecursoEvaluador);
	
	@Query(value="select count(distinct(cod_recurso_evaluador)) evaluados from RESULTADOS_COMPETENCIAS where cod_recurso = ?1 and cod_evaluacion_desempeno = ?2", nativeQuery = true)
	public Long getTotalEvaluadosByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion);
	
	@Query("select new com.sophi.app.models.entity.RespuestaCompetencia(codCompetencias, descReactivo, avg(valResultado)) "+
	"from RespuestaCompetencia " + 
	"where codRecurso = ?1 and codEvaluacionDesempeno = ?2 and valTipoEvaluador = ?3 "+
	"group by codCompetencias, descReactivo order by codCompetencias")
	public List<RespuestaCompetencia> getRespuestasPromedioEvaluadores(Long codRecurso, Long codEvaluacion, Long tipo);
}
