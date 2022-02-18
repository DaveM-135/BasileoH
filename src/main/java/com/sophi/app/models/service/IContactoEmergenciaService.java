package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.ContactoEmergencia;

public interface IContactoEmergenciaService {
	
	public List<ContactoEmergencia> findAll();
	
	public void save(ContactoEmergencia contactoEmergencia);
	
	public ContactoEmergencia findOne(Long codContactoEmergencia);
	
	public void delete(ContactoEmergencia contactoEmergencia);
	
	public List<ContactoEmergencia> findByCodRecurso(Long codRecurso);

}
