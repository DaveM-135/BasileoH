package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITipoSangreDao;
import com.sophi.app.models.entity.TipoSangre;

@Service
public class TipoSangreServiceImpl implements ITipoSangreService{
	
	@Autowired
	private ITipoSangreDao tipoSangreDao;

	@Override
	@Transactional(readOnly = true)
	public List<TipoSangre> findAll() {
		return (List<TipoSangre>) tipoSangreDao.findAll();
	}

}
