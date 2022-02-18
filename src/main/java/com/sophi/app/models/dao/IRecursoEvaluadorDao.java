package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.RecursoEvaluador;

public interface IRecursoEvaluadorDao extends CrudRepository<RecursoEvaluador, Long> {

	public List<RecursoEvaluador> findByCodEvaluacionDesempenoAndCodRecurso(Long codEvaluacionDesempeno, Long  codRecurso);

	public List<RecursoEvaluador> findByCodEvaluacionDesempenoAndCodEvaluador(Long codEvaluacionDesempeno, Long codEvaluador);
	
	public List<RecursoEvaluador> findByCodEvaluacionDesempeno(Long codEvaluacionDesempeno);
	
	@Modifying
    @Query("delete from RecursoEvaluador re where re.codRecurso = ?1 and re.codEvaluacionDesempeno = ?2")
    public void deleteRecursoEvaluadorByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacionDesempeno);
	
}
