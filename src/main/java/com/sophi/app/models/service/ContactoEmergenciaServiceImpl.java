package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IContactoEmergenciaDao;
import com.sophi.app.models.entity.ContactoEmergencia;

@Service
public class ContactoEmergenciaServiceImpl implements IContactoEmergenciaService {
	
	@Autowired
	private IContactoEmergenciaDao contactoEmergenciaDao;

	@Override
	@Transactional(readOnly = true)
	public List<ContactoEmergencia> findAll() {
		return (List<ContactoEmergencia>) contactoEmergenciaDao.findAll();
	}

	@Override
	@Transactional
	public void save(ContactoEmergencia contactoEmergencia) {
		contactoEmergenciaDao.save(contactoEmergencia);
	}

	@Override
	@Transactional(readOnly = true)
	public ContactoEmergencia findOne(Long codContactoEmergencia) {
		return contactoEmergenciaDao.findById(codContactoEmergencia).orElse(null);
	}

	@Override
	@Transactional
	public void delete(ContactoEmergencia contactoEmergencia) {
		contactoEmergenciaDao.delete(contactoEmergencia);
	}

	@Override
	@Transactional(readOnly = true)
	public List<ContactoEmergencia> findByCodRecurso(Long codRecurso) {
		return contactoEmergenciaDao.findByCodRecurso(codRecurso);
	}

}
