package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Metas;

public interface IMetasService {

	public List<Metas> findAll();
	
	public Metas findById(Long codMeta);
	
	public Metas findByDescMeta(String descMeta);
	
	public void guardar(Metas meta);
}
