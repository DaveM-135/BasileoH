package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Cargo;

public interface ICargoService {
	
	public List<Cargo> findAll();
	
	public void save(Cargo cargo);
	
	public void delete(Long codCargo);
	
	public Cargo findOne(Long codCargo);

}
