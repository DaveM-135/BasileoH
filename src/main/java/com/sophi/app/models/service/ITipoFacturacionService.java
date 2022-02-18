package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.TipoFacturacion;

public interface ITipoFacturacionService {
	
	public List<TipoFacturacion> findAll();
	
	public void save(TipoFacturacion tipoFacturacion);
	
	public TipoFacturacion findOne(Long tipoFacturacion);
	

}
