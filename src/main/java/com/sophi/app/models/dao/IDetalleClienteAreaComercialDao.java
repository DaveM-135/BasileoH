package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.DetalleClienteAreaComercial;

public interface IDetalleClienteAreaComercialDao extends CrudRepository<DetalleClienteAreaComercial, Long>{
	
	List<DetalleClienteAreaComercial> findByDetalleClienteAreaComercialIdCodCliente(Long codCliente);
	
}