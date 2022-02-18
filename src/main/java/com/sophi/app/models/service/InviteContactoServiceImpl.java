package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IInviteContactoDao;
import com.sophi.app.models.entity.InviteContacto;

@Service
public class InviteContactoServiceImpl implements IInviteContactoService{
	
	@Autowired
	private IInviteContactoDao inviteContactoDao;

	@Override
	@Transactional(readOnly = true)
	public List<InviteContacto> findAll() {
		return (List<InviteContacto>) inviteContactoDao.findAll();
	}

}
