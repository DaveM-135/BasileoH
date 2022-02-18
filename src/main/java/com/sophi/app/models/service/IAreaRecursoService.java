package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.AreaRecurso;

public interface IAreaRecursoService {
	
	public List<AreaRecurso> findAll();
	
	public void save(AreaRecurso areaRecurso);
	
	public AreaRecurso findOne(Long codAreaRecurso);

}
