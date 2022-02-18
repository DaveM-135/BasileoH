package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IParentescoDao;
import com.sophi.app.models.entity.Parentesco;

@Service
public class ParentescoServiceImpl implements IParentescoService {
	
	@Autowired
	private IParentescoDao parentescoDao;

	@Override
	@Transactional(readOnly = true)
	public List<Parentesco> findAll() {
		return (List<Parentesco>) parentescoDao.findAll();
	}

}
