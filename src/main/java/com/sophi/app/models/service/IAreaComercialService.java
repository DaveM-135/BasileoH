package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.AreaComercial;

public interface IAreaComercialService {
	
	public List<AreaComercial> findAll();
	
	public void save(AreaComercial areaComercial);
	
	public AreaComercial findOne(Long codAreaComercial);

}
