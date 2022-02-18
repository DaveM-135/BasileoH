package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoTrayectoriaNivelDao;
import com.sophi.app.models.entity.RecursoTrayectoriaNivel;

@Service
public class RecursoTrayectoriaNivelServiceImpl implements IRecursoTrayectoriaNivelService{
	
	@Autowired
	private IRecursoTrayectoriaNivelDao recursoTrayectoriaNivelDao;

	@Override
	@Transactional(readOnly = true)
	public List<RecursoTrayectoriaNivel> findByCodRecurso(Long codRecurso) {
		return recursoTrayectoriaNivelDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public RecursoTrayectoriaNivel findById(Long codRecursoTrayectoriaRecurso) {
		return recursoTrayectoriaNivelDao.findById(codRecursoTrayectoriaRecurso).orElse(null);
	}

	@Override
	@Transactional
	public void save(RecursoTrayectoriaNivel recursoTrayectoriaNivel) {
		recursoTrayectoriaNivelDao.save(recursoTrayectoriaNivel);
	}

	@Override
	@Transactional
	public void delete(Long codRecursoTrayectoriaNivel) {
		recursoTrayectoriaNivelDao.deleteById(codRecursoTrayectoriaNivel);
	}

	@Override
	@Transactional(readOnly = true)
	public RecursoTrayectoriaNivel findByCodRecursoAndCodConocimiento(Long codRecurso, Long codConocimiento) {
		return recursoTrayectoriaNivelDao.findByCodRecursoAndCodConocimiento(codRecurso, codConocimiento);
	}

	
	
}
