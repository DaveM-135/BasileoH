package com.sophi.app.models.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IMesHabilDao;
import com.sophi.app.models.entity.MesHabil;

@Service
public class MesHabilServiceImpl implements IMesHabilService{
	
	@Autowired
	private IMesHabilDao mesHabilDao;

	@Override
	@Transactional(readOnly = true)
	public MesHabil findById(Long id) {
		return mesHabilDao.findById(id).orElse(null);
	}

}
