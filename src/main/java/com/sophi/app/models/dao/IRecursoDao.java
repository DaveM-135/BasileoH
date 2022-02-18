package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RecursoIdNombre;

public interface IRecursoDao extends CrudRepository<Recurso, Long>{

	Recurso findByDescCorreoElectronico(String correoElectronico);

	@Query("FROM Recurso R WHERE LOWER(R.descRecurso) LIKE LOWER(concat('%',?1, '%')) AND LOWER(R.descApellidoPaterno) LIKE LOWER(concat('%',?2, '%'))")
	List<Recurso> findByNombreApellido(String descRecurso, String descApellidoPaterno);
	
	@Query("FROM Recurso R WHERE R.valActivo = 1")
	List<Recurso> findRecursosActivos();
	
	@Query("FROM Recurso R WHERE R.valResponsable = 1")
	List<Recurso> findListRecursosResponsables();
	
	@Query("FROM Recurso R WHERE R.valAprobador = 1 AND R.codRecurso != ?1")
	List<Recurso> findListRecursosAprobadoresBKP(Long codRecurso);
	
	@Query("FROM Recurso R WHERE R.valAprobador = 1")
	List<Recurso> findListRecursosAprobadores();
	
	Recurso findByCodRecurso(Long codRecurso);
	
	List<Recurso> findByCodAreaRecurso(Long codAreaRecurso);
	
	@Query("FROM Recurso R WHERE R.valActivo = 1 and R.codPerfil = ?1")
	List<Recurso> findRecursosByPerfil(Long codPerfil);
	
	@Query(value = "SELECT new com.sophi.app.models.entity.RecursoIdNombre(codRecurso as id, descRecurso as nombre, descApellidoPaterno as apellido) FROM Recurso WHERE valActivo = 1")
	public List<RecursoIdNombre> recursosActivosOnlyIdNombre();
	
	@Query("SELECT CONCAT(descRecurso,' ',descApellidoPaterno) FROM Recurso R WHERE R.codRecurso = ?1")
	public String getNombreApellidoById(Long codRecurso);
	
	@Query("SELECT CONCAT(descRecurso,' ',descApellidoPaterno, ' - ', puesto.descPuesto) FROM Recurso R WHERE R.codRecurso = ?1")
	public String getNombreApellidoPuestoById(Long codRecurso);
	
	@Query("SELECT R.descCorreoElectronico FROM Recurso R WHERE R.codRecurso = ?1")
	public String getEmailRecursoById(Long codRecurso);
}
