package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRolDao;
import com.sophi.app.models.entity.Rol;

@Service
public class RolServiceImpl implements IRolService{

	@Autowired
	private IRolDao rolDao;
	
	@Override
	public List<Rol> findListaRoles() {
		return rolDao.findListaRoles();
	}

	@Override
	public List<Rol> findByCodRecurso(Long codRecurso) {
		return rolDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<String> getListaAdminRh() {
		return rolDao.getListaAdminRh();
	}

}
