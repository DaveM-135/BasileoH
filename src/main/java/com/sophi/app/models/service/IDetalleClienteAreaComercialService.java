package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.DetalleClienteAreaComercial;

public interface IDetalleClienteAreaComercialService {
	
	public List<DetalleClienteAreaComercial> findByDetalleClienteAreaComercialIdCodCliente(Long codCliente);
	
	public void save(DetalleClienteAreaComercial detalleClienteAreaComercial);
}
