package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.TipoProyecto;

public interface ITipoProyectoService {
	
	public List<TipoProyecto> findAll();
	
	public void save(TipoProyecto tipoProyecto);
	
	public TipoProyecto findOne(Long tipoProyecto);
	

}
