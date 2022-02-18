package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Equipo;

public interface IEquipoService {

	public List<Equipo> findAll();

	public Equipo findByCodEstadoHerramienta(Long codEstadoHerramienta);
	
	public List<Equipo> findByCodTipoHerramienta(Long codTipoHerramienta);
	
	public Equipo findByCodHerramienta(Long codHerramienta);
	
	public List<Equipo> findListEquiposDisponibles();
	
	public List<Equipo> findListEquiposDisponiblesPorTipoHerramienta(Long codTipoHerramienta);

}
