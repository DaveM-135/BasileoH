package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IDetalleClienteAreaComercialDao;
import com.sophi.app.models.entity.DetalleClienteAreaComercial;

@Service
public class DetalleClienteAreaComercialServiceImpl implements IDetalleClienteAreaComercialService {
	
	@Autowired
	private IDetalleClienteAreaComercialDao detalleClienteAreaComercialDao;

	@Override
	@Transactional(readOnly = true)
	public List<DetalleClienteAreaComercial> findByDetalleClienteAreaComercialIdCodCliente(Long codCliente) {
		return (List<DetalleClienteAreaComercial>) detalleClienteAreaComercialDao.findByDetalleClienteAreaComercialIdCodCliente(codCliente);
	}
	
	@Override
	public void save(DetalleClienteAreaComercial ac) {
		detalleClienteAreaComercialDao.save(ac);
	}

}
