package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IExpedienteDigitalDao;
import com.sophi.app.models.entity.ExpedienteDigital;

@Service
public class ExpedienteDigitalServiceImpl implements IExpedienteDigitalService{
	
	@Autowired
	private IExpedienteDigitalDao expedienteDigitalDao;

	@Override
	@Transactional(readOnly = true)
	public List<ExpedienteDigital> findByCodRecurso(Long codRecurso) {
		return expedienteDigitalDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public ExpedienteDigital findById(Long codExpedienteDigital) {
		return expedienteDigitalDao.findById(codExpedienteDigital).orElse(null);
	}

	@Override
	@Transactional
	public void save(ExpedienteDigital expedienteDigital) {
		expedienteDigitalDao.save(expedienteDigital);
	}

	@Override
	@Transactional
	public void delete(Long codExpedienteDigital) {
		expedienteDigitalDao.deleteById(codExpedienteDigital);
	}

	@Override
	public ExpedienteDigital findByCodRecursoAndCodDocumento(Long codRecurso, Long codDocumento) {
		return expedienteDigitalDao.findByCodRecursoAndCodDocumento(codRecurso, codDocumento);
	}

}
