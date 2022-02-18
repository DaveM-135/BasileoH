package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IHistoricoRespuestaClimaDao;
import com.sophi.app.models.entity.HistRespuestaAux;

@Service
public class HistoricoRespuestaClimaServiceImpl implements IHistoricoRespuestaClimaService{
	
	@Autowired
	private IHistoricoRespuestaClimaDao historicoRespuestaClimaDao;

	@Override
	@Transactional(readOnly = true)
	public List<HistRespuestaAux> resultados(long idDia) {
		return historicoRespuestaClimaDao.resultados(idDia);
	}

	@Override
	@Transactional(readOnly = true)
	public Integer totalParticipacion(long idDia) {
		return historicoRespuestaClimaDao.totalParticipacion(idDia);
	}

}
