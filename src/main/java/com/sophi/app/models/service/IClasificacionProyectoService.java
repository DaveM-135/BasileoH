package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.ClasificacionProyecto;

public interface IClasificacionProyectoService {
	
	public List<ClasificacionProyecto> findAll();
	
	public void save(ClasificacionProyecto clasificacionProyecto);
	
	public ClasificacionProyecto findOne(Long codClasificacionProyecto);

}
