package com.sophi.app.models.dao;

import java.util.Date;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.EvaluacionDesempeno;

public interface IEvaluacionDesempenoDao extends CrudRepository<EvaluacionDesempeno, Long>{
	
	@Modifying
	@Query("UPDATE EvaluacionDesempeno Ed SET Ed.valEstatus = ?2, Ed.fecCierre = ?3, Ed.valPromedioEmpresa = ?4 where Ed.codEvaluacionDesempeno = ?1")
	void updateCierreEvaluacionDesempeno(Long codEvaluacionDesempeno,Long valEstatus,Date fecCierre, Float promedioEmpresa);
	
	//Calculos de METAS
	
	//Captura de horas
	@Query(value="select sum(val_horas_habiles) horasHabiles from CAT_DIAS_HABILES where mes_id between ?1 and ?1", nativeQuery = true)
	Float getHorasHabilesByMes(Long mesIdInicio, Long mesIdFin);
	
	@Query(value="select sum(val_duracion_validada) horasValidadas from RECURSOS_CAP_HORAS where cod_recurso = ?1 and fec_inicio_actividad between ?2 and ?3", nativeQuery = true)
	Float getHorasHabilesValidadasByCodRecursoAndMes(Long codRecurso, Date fecInicio, Date fecFin);

	//CSI
	@Query(value="select avg(dep.calificacion) calificacion from DETALLE_EVALUACION_PROYECTO dep where dep.cod_concepto = 7016 and dep.cod_proyecto in ( "+
			"select distinct(rch.cod_proyecto)  from RECURSOS_CAP_HORAS rch where rch.cod_recurso = 4 and rch.fec_inicio_actividad between '2021-01-01' and '2021-01-31')", nativeQuery = true)
	Float getAvgCsiByCodRecursoAndMes(Long codRecurso, Date fecInicio, Date fecFin);
}
