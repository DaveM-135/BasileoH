package com.sophi.app.models.dao;

import com.sophi.app.models.entity.AprobacionGastos;

import java.util.Date;
import java.util.List;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

public interface IAprobacionGastosDao extends CrudRepository<AprobacionGastos, Long> {
    
	@Query("FROM AprobacionGastos Ap WHERE Ap.codProyecto = ?1 AND Ap.codRecursoValidador IS NULL AND Ap.valImporteValidado IS NULL AND Ap.fecValidacion IS NULL ")
    List<AprobacionGastos> findAprobacionGastosBycodProyecto(Long codProyecto);
	
//	@Query("FROM AprobacionGastos Ap WHERE Ap.codRecursoValidador IS NULL ")
//    List<AprobacionGastos> findAprobacionGastosGeneral();
	
	@Query("FROM AprobacionGastos Ap INNER JOIN Proyecto Pr ON Ap.codProyecto = Pr.codProyecto WHERE Ap.codRecursoValidador IS NULL AND Pr.codEstatusProyecto = 2")
	List<AprobacionGastos> findAprobacionGastosGeneral();
	
	
	@Modifying
	@Query("UPDATE AprobacionGastos Ag SET Ag.codRecursoValidador = :codValidador, Ag.fecValidacion = :fecValidacion, Ag.valImporteValidado = :valImporteValidado, Ag.valGastoPlaneado = :valGastoPlaneado where Ag.codRecursoGasto = :codRecursoGasto")
	void updateValidacion(@Param("codValidador") Long codValidador,@Param("fecValidacion") Date fecValidacion, @Param("valImporteValidado") Float valImporteValidado, @Param("valGastoPlaneado") Long valGastoPlaneado, @Param("codRecursoGasto") Long codRecursoGasto);
	
}