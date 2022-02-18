package com.sophi.app.models.dao;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

import com.sophi.app.models.entity.Agenda;

public interface IAgendaDao extends CrudRepository<Agenda, Long>{

    @Query("FROM Agenda a WHERE a.codCliente = ?1")
    List<Agenda> findContactosBycodCliente(Long codCliente);

}