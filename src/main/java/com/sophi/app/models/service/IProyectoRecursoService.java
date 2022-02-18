package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.ProyectoRecurso;
import com.sophi.app.models.entity.ProyectoRecursoId;

public interface IProyectoRecursoService {
	
	public List<ProyectoRecurso> findAll();
	
	public void save(ProyectoRecurso proyectoRecurso);
	
	public ProyectoRecurso findOne(ProyectoRecursoId proyectoRecurso);
	
	public void delete(ProyectoRecurso proyectoRecurso);
	
	public List<ProyectoRecurso> findByProyectoRecursoIdCodRecurso(Long codRecurso);
	
	public void saveAll(List<ProyectoRecurso> proyectoRecurso);
	
	public List<ProyectoRecurso> findByProyectoRecursoIdCodProyecto(Long codProyecto);
	
	public List<ProyectoRecurso> findProyectoRecursoActivo(Long codRecurso);	
}
