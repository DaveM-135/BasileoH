package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Equipo;

public interface IEquipoDao extends CrudRepository<Equipo, Long>{
	
	public Equipo findByCodEstadoHerramienta(Long codEstadoHerramienta);
	
	public List<Equipo> findByCodTipoHerramienta(Long codTipoHerramienta);
	
	public Equipo findByCodHerramienta(Long codHerramienta);
	
	@Query("FROM Equipo E WHERE E.codEstadoHerramienta = 1")
	List<Equipo> findListEquiposDisponibles();
	
	@Query("FROM Equipo E WHERE E.codEstadoHerramienta = 1 AND E.codTipoHerramienta = ?1")
	List<Equipo> findListEquiposDisponiblesPorTipoHerramienta(Long codTipoHerramienta);
	
}
