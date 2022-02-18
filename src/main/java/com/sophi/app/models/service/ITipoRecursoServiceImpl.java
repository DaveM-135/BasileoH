package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITipoRecursoDao;
import com.sophi.app.models.entity.TipoRecurso;

@Service
public class ITipoRecursoServiceImpl implements ITipoRecursoService {
	
	@Autowired
	private ITipoRecursoDao tipoRecursoDao;

	@Override
	@Transactional(readOnly = true)
	public List<TipoRecurso> findAll() {
		return (List<TipoRecurso>) tipoRecursoDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public TipoRecurso findOne(Long codTipoRecurso) {
		return tipoRecursoDao.findById(codTipoRecurso).orElse(null);
	}

}
