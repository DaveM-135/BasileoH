package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.DiaFestivo;

public interface IDiaFestivoService {
	
	public List<DiaFestivo> findAll();
	
	public List<DiaFestivo> findByCodDiaFestivoPorMes(Long inicioMes, Long finMes);
	
	public void save(DiaFestivo diaFestivo);
	
	public void delete(Long codDiaFestivo);
	
	public List<DiaFestivo> findEsNoLaboral(Long codDiaFestivo);

}
