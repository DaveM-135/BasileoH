package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IAreaRecursoDao;
import com.sophi.app.models.entity.AreaRecurso;

@Service
public class AreaRecursoServiceImpl implements IAreaRecursoService {

	@Autowired
	private IAreaRecursoDao areaRecursoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<AreaRecurso> findAll() {
		return (List<AreaRecurso>) areaRecursoDao.findAll();
	}

	@Override
	@Transactional
	public void save(AreaRecurso areaRecurso) {
		areaRecursoDao.save(areaRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public AreaRecurso findOne(Long codAreaRecurso) {
		return areaRecursoDao.findById(codAreaRecurso).orElse(null);
	}

	
}
