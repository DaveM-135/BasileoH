package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Metas;

public interface IMetaDao extends CrudRepository<Metas, Long>{

	public Metas findByDescMeta(String descMeta);
	
}
