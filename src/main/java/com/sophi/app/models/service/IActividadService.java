package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Actividad;

public interface IActividadService {

	public List<Actividad> findAll();
	
	public void save(Actividad actividad);
	
	public void saveAll(Iterable<Actividad> actividades);
	
	public Actividad findOne(Long codActividad);
	
	public void delete(Actividad actividad);
	
	public List<Long> findListaProyectoByRecurso(Long codRecurso);
	
	public List<Actividad> findListaActividadesByRecursoProyecto(Long codRecurso, Long codProyecto);
	
	public List<String> findListaActividadesPrimariasByRecursoProyecto(Long codRecurso, Long codProyecto);
	
	public List<Actividad> findListaActividadesByRecursoProyectoPrimaria(Long codRecurso, Long codProyecto, String descPrimaria);
	
	public List<Actividad> findByCodRecurso(Long codRecurso);
	
	public long countByCodProyecto(Long codProyecto);
	
	public  List<Actividad> findByCodProyecto(Long codProyecto);
	
	public Float sumTotalHorasProyecto(Long codRecurso, Long codProyecto);
	
}
