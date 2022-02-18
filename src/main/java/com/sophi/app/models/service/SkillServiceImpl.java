package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ISkillDao;
import com.sophi.app.models.entity.Skill;

@Service
public class SkillServiceImpl implements ISkillService {

	@Autowired
	private ISkillDao skillDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Skill> findAll() {
		return (List<Skill>) skillDao.findAll();
	}

	@Override
	@Transactional
	public void save(Skill skill) {
		skillDao.save(skill);
	}

	@Override
	@Transactional(readOnly = true)
	public Skill findOne(Long codSkill) {
		return skillDao.findById(codSkill).orElse(null);
	}

	@Override
	@Transactional
	public void delete(Skill skill) {
		skillDao.delete(skill);
	}

}
