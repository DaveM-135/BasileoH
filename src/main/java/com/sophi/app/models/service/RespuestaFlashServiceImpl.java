package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRespuestaFlashDao;
import com.sophi.app.models.entity.RespuestaFlash;

@Service
public class RespuestaFlashServiceImpl implements IRespuestaFlashService{
	
	@Autowired
	private IRespuestaFlashDao respuestaFlashDao;

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaFlash> findAll() {
		return (List<RespuestaFlash>) respuestaFlashDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public RespuestaFlash findByCodRespuesta(Long codRespuesta) {
		return respuestaFlashDao.findById(codRespuesta).orElse(null);
	}

}
