package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.DetalleClienteInfraestructura;

public interface IDetalleClienteInfraestructuraService {
	
	public List<DetalleClienteInfraestructura> findAll();
	
	public void save(DetalleClienteInfraestructura detalleClienteInfraestructura);
	
}
