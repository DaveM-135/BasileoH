package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.PerfilRecurso;

public interface IPerfilRecursoDao extends CrudRepository<PerfilRecurso, Long>{

	PerfilRecurso findByCodPerfil(Long codPerfil);
	
	@Query("SELECT COUNT(*) FROM Recurso r WHERE r.codPerfil = ?1 AND r.valActivo = 1")
	public Long totalRecursosAsignados(Long codPerfil);
	
	 public List<PerfilRecurso> findAllByOrderByValOrdenAsc();

}
