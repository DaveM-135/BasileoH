package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Sector;

public interface ISectorService {
	
	public List<Sector> findAll();
	
	public void save(Sector sector);
	
	public Sector findOne(Long codSector);

}
