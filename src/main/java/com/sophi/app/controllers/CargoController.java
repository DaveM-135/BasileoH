package com.sophi.app.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.sophi.app.models.dao.ICargoDao;

@Controller
public class CargoController {

	@Autowired
	private ICargoDao cargoDao;
	
	@RequestMapping(value = "/listarCargos", method = RequestMethod.GET)
	public String listar(Model model) {
		model.addAttribute("titulo", "Listado de cargos");
		model.addAttribute("cargos", cargoDao.findAll());
		return "listaCargos";
	}
	
}
