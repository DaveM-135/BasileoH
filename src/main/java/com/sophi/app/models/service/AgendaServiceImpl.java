package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IAgendaDao;
import com.sophi.app.models.entity.Agenda;

@Service
public class AgendaServiceImpl implements IAgendaService {
	
	@Autowired
	private IAgendaDao agendaDao;

	@Override
	@Transactional(readOnly = true)
	public List<Agenda> findAll() {
		return (List<Agenda>) agendaDao.findAll();
	}

	@Override
	public void save(Agenda contacto) {
		agendaDao.save(contacto);
	}

	@Override
	@Transactional(readOnly = true)
	public Agenda findOne(Long codContacto) {
		return agendaDao.findById(codContacto).orElse(null);
	}

	@Override
	public void delete(Long codContacto) {
		agendaDao.deleteById(codContacto);
		
	}

	@Override
	public List<Agenda> findContactosBycodCliente(Long codCliente) {
		return agendaDao.findContactosBycodCliente(codCliente);
	}

}
