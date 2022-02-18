package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RecursoTrayectoriaNivel;

public interface IRecursoTrayectoriaNivelService {
	
	public List<RecursoTrayectoriaNivel> findByCodRecurso(Long codRecurso);
	
	public RecursoTrayectoriaNivel findById(Long codRecursoTrayectoriaRecurso);
	
	public void save(RecursoTrayectoriaNivel recursoTrayectoriaNivel);
	
	public void delete(Long codRecursoTrayectoriaNivel);
	
	public RecursoTrayectoriaNivel findByCodRecursoAndCodConocimiento(Long codRecurso, Long codConocimiento);

}
