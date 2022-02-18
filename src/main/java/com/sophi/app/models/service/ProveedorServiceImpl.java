package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IProveedorDao;
import com.sophi.app.models.entity.Proveedor;

@Service
public class ProveedorServiceImpl implements IProveedorService {

	@Autowired
	private IProveedorDao proveedorDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Proveedor> findAll() {
		return (List<Proveedor>) proveedorDao.findAll();
	}

	@Override
	@Transactional
	public void save(Proveedor proveedor) {
		proveedorDao.save(proveedor);
	}

	@Override
	@Transactional(readOnly = true)
	public Proveedor findOne(Long codProveedor) {
		return proveedorDao.findById(codProveedor).orElse(null);
	}

}
