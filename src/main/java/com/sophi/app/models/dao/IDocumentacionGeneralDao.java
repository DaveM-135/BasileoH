package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.DocumentacionGeneral;

public interface IDocumentacionGeneralDao extends CrudRepository<DocumentacionGeneral, Long> {

}
