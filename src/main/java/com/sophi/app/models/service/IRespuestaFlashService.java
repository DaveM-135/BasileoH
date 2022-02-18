package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RespuestaFlash;

public interface IRespuestaFlashService {
	
	public List<RespuestaFlash> findAll();
	
	public RespuestaFlash findByCodRespuesta(Long codRespuesta);

}
