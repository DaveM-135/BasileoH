package com.sophi.app.models.dao;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

import com.sophi.app.models.entity.AprobacionHoras;

public interface IAprobacionHorasDao extends CrudRepository<AprobacionHoras, Long> {

    @Query("FROM AprobacionHoras Ap WHERE Ap.codProyecto = ?1")
    List<AprobacionHoras> findAprobacionHorasBycodProyecto(Long codProyecto);
    
    @Query("FROM AprobacionHoras Ap WHERE Ap.codRecursoValidador IS NULL AND Ap.codProyecto = ?1 ")
    List<AprobacionHoras> findAprobacionHorasGeneral(Long codProyecto);
    
//  @Query("FROM AprobacionHoras Ap INNER JOIN Proyecto Pr ON Ap.codProyecto = Pr.codProyecto WHERE Ap.codRecursoValidador IS NULL AND Pr.codEstatusProyecto = 2 ")
//  List<AprobacionHoras> findAprobacionHorasGeneral();
    
}
