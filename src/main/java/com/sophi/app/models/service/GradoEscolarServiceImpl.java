package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IGradoEscolarDao;
import com.sophi.app.models.entity.GradoEscolar;

@Service
public class GradoEscolarServiceImpl implements IGradoEscolarService{
	
	@Autowired
	private IGradoEscolarDao gradoEscolarDao;

	@Override
	@Transactional(readOnly = true)
	public List<GradoEscolar> findAll() {
		return (List<GradoEscolar>) gradoEscolarDao.findAll();
	}

}
