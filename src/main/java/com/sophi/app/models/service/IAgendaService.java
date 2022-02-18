package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Agenda;

public interface IAgendaService {
	
	public List<Agenda> findAll();
	
	public void save(Agenda contacto);
	
	public void delete(Long codContacto);
	
	public Agenda findOne(Long codContacto);

	public List<Agenda> findContactosBycodCliente(Long codCliente);
	
}
