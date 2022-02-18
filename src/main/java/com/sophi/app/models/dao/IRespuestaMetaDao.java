package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface IRespuestaMetaDao extends CrudRepository<RespuestaMeta, Long> {
	
	List<RespuestaMeta> findByCodRecursoAndCodEvaluacionDesempenoOrderByCodMeta(Long codRecurso, Long codEvaluacionDesempeno);
	
	@Query(value="SELECT SUM(val_resultado_porcentaje) as promedioCompetencias FROM REsultados_metas where cod_recurso = ?1 and cod_evaluacion_desempeno = ?2", nativeQuery = true)
	public Float getPromedioMetasByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion);
	
	@Query(value="select cast(round(avg(resultadoMeta),1) AS DEC(10,2)) as promedioMeta from ("
			+ "select cod_recurso, sum(val_resultado_porcentaje) as resultadoMeta from resultados_metas where cod_evaluacion_desempeno = ?1 group by cod_recurso) meta", nativeQuery = true)
	public Float getPromedioMetasByCodEvaluacion(Long codEvaluacion);
	
	

}
