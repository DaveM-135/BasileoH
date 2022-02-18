package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Skill;

public interface ISkillService {
	
	public List<Skill> findAll();
	
	public void save(Skill skill);
	
	public Skill findOne(Long codSkill);
	
	public void delete(Skill skill);

}
