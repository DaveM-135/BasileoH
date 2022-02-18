package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IMetaDao;
import com.sophi.app.models.entity.Metas;

@Service
public class MetasServiceImpl implements IMetasService {
	
	@Autowired
	private IMetaDao metaDao;

	@Override
	@Transactional(readOnly = true)
	public List<Metas> findAll() {
		return (List<Metas>) metaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Metas findById(Long codMeta) {
		return metaDao.findById(codMeta).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public Metas findByDescMeta(String descMeta) {
		return metaDao.findByDescMeta(descMeta);
	}

	@Override
	@Transactional
	public void guardar(Metas meta) {
		metaDao.save(meta);
	}

	
}
