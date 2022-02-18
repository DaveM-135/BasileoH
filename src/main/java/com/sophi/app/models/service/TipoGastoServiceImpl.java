package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITipoGastoDao;
import com.sophi.app.models.entity.TipoGasto;
@Service
public class TipoGastoServiceImpl implements ITipoGastoService {

	@Autowired
	private ITipoGastoDao tipoGastoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<TipoGasto> findAll() {
		return (List<TipoGasto>) tipoGastoDao.findAll();
	}

	@Override
	@Transactional
	public void save(TipoGasto tipoGasto) {
		tipoGastoDao.save(tipoGasto);
	}

	@Override
	@Transactional(readOnly = true)
	public TipoGasto findOne(Long tipoGasto) {
		return tipoGastoDao.findById(tipoGasto).orElse(null);
	}

}
