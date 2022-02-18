package com.sophi.app.controllers;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.sophi.app.models.entity.Capacitaciones;
import com.sophi.app.models.service.ICapacitacionesService;
import com.sophi.app.models.service.IRecursoCapacitacionService;

@Controller
public class CapacitacionController {
	
	@Autowired
	private ICapacitacionesService capacitacionesService;
	
	@Autowired
	private IRecursoCapacitacionService recursoCapacitacionService;
	
	@RequestMapping(value = "/capacitaciones")
	public String verCapacitaciones(Map<String, Object> model) {
		List<Capacitaciones> listaCapacitaciones = capacitacionesService.findAll();
		for (Capacitaciones capacitaciones : listaCapacitaciones) {
			Long tot = recursoCapacitacionService.countByCodCapacitacion(capacitaciones.getCodCapacitacion());
			if(tot > 0) {
				capacitaciones.setValBorrar(0L);
			} else {
				capacitaciones.setValBorrar(1L);
			}
		}
		
		
		model.put("listaCapacitaciones", capacitacionesService.findAll());
		model.put("capacitacion", new Capacitaciones());
		return "listaCapacitaciones";
	}
	
	
	@RequestMapping(value = "/formCapacitaciones")
	public String crearCapacitaciones(Map<String, Object> model) {
		model.put("capacitacion", new Capacitaciones());
		return "listaCapacitaciones :: fragmentModalCapacitaciones";
	}
	
	@RequestMapping(value="/formCapacitaciones", method = RequestMethod.POST)
	public String guardarCapacitaciones(@ModelAttribute Capacitaciones capacitacion, Model model) {
		capacitacionesService.save(capacitacion);
		return "redirect:/capacitaciones";
	}
	
	@RequestMapping(value = "/editarCapacitaciones")
	public String editarCapacitaciones(@RequestParam("c") Long codCapacitacion, Map<String, Object> model) {
		model.put("capacitacion",capacitacionesService.findById(codCapacitacion));
		return "listaCapacitaciones :: fragmentModalCapacitaciones";
	}
	
	@RequestMapping(value = "/eliminarCapacitacion")
	@ResponseBody
	public String eliminarCapacitacion(@RequestParam("c") Long codCapacitacion, Map<String, Object> model) {
		capacitacionesService.delete(codCapacitacion);
		return "1";
	}
	
	
	

}
