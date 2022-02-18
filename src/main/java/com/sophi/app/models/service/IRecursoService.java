package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RecursoIdNombre;

public interface IRecursoService {
	
	List<Recurso> listaRecursos();

	public List<Recurso> findAll();
	
	public void save(Recurso recurso);
	
	public Recurso findOne(Long codRecurso);
	
	public List<Recurso> findByNombreApellido(String descRecurso, String descApellidoPaterno);
	
	public Recurso findByDescCorreoElectronico(String correoElectronico);
	
	public List<Recurso> findRecursosActivos();
	
	public List<Recurso> findListRecursosResponsables();
	
	public List<Recurso> findListRecursosAprobadores();
	
	public List<Recurso> findListRecursosAprobadoresBKP(Long codRecurso);
	
	public List<Recurso> findByCodAreaRecurso(Long codAreaRecurso);
	
	public List<Recurso> findRecursosByPerfil(Long codPerfil);

	public List<RecursoIdNombre> findActivosOnlyIdNombre();
	
	public String getNombreApellidoById(Long codRecurso);
	
	public String getNombreApellidoPuestoById(Long codRecurso);
	
	public String getEmailRecursoById(Long codRecurso);
	
}
