package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Conocimientos;

public interface IConocimientoService {

	public Conocimientos findById(Long codConocimiento);
	
	public List<Conocimientos> findAll();
	
	public List<Conocimientos> findByCodTipoConocimiento(Long codTipoConocimiento);
		
}
