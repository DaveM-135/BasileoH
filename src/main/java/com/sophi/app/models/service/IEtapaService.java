package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Etapa;

public interface IEtapaService {
	
	public Etapa findByCodEtapa(Long codEtapa);
	
	public List<Etapa> findAll();

}
