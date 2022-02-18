package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITipoProyectoDao;
import com.sophi.app.models.entity.TipoProyecto;

@Service
public class TipoProyectoServiceImpl implements ITipoProyectoService {

	@Autowired
	private ITipoProyectoDao tipoProyectoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<TipoProyecto> findAll() {
		return (List<TipoProyecto>) tipoProyectoDao.findAll();
	}

	@Override
	@Transactional
	public void save(TipoProyecto tipoProyecto) {
		tipoProyectoDao.save(tipoProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public TipoProyecto findOne(Long tipoProyecto) {
		return tipoProyectoDao.findById(tipoProyecto).orElse(null);
	}

	
}
