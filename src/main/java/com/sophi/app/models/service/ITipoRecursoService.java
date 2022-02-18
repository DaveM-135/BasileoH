package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.TipoRecurso;

public interface ITipoRecursoService {
	
	public List<TipoRecurso> findAll();
	
	public TipoRecurso findOne(Long codTipoRecurso);


}
