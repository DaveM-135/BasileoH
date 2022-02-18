package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Skill;

public interface ISkillDao extends CrudRepository<Skill, Long>{

}
