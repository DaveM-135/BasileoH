package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.DiaFestivo;

public interface IDiaFestivoDao extends CrudRepository<DiaFestivo, Long>{
	
	@Query("FROM DiaFestivo D WHERE D.codDiaFestivo BETWEEN ?1 AND ?2")
	List<DiaFestivo> findByCodDiaFestivo(Long inicioMes, Long finMes);
	
	@Query("FROM DiaFestivo D WHERE D.codDiaFestivo = ?1 AND D.valEsNolaboral = 1 ")
	List<DiaFestivo> findEsNoLaboral(Long codDiaFestivos);
}
