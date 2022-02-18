package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.TipoGasto;

public interface ITipoGastoService {
	
	public List<TipoGasto> findAll();
	
	public void save(TipoGasto tipoGasto);
	
	public TipoGasto findOne(Long tipoGasto);
	
}
