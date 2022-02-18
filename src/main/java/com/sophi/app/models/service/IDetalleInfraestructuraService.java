package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.DetalleInfraestructura;

public interface IDetalleInfraestructuraService {
	
	public List<DetalleInfraestructura> findAll();
	
	public void save(DetalleInfraestructura detalleInfraestructura);
	
	public DetalleInfraestructura findOne(Long cod_detalle_infraestructura);
	
}
