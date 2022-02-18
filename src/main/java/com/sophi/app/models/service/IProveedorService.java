package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Proveedor;

public interface IProveedorService {
	
	public List<Proveedor> findAll();
	
	public void save(Proveedor proveedor);
	
	public Proveedor findOne(Long codProveedor);

}
