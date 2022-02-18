package com.sophi.app.controllers;

import java.util.Map;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.Sueldo;
import com.sophi.app.models.service.IRecursoService;
import com.sophi.app.models.service.ISueldoService;

@Controller
@SessionAttributes("sueldo")
public class SueldoController {
	
	@Autowired
	private IRecursoService recursoService;
	
	@Autowired
	private ISueldoService sueldoService;
	
	@RequestMapping(value = "/listarSueldos/{id}")
	public String listarSueldos(@PathVariable(value = "id") Long codRecurso, Map<String, Object> model, RedirectAttributes flash) {
		Recurso recurso = null;
		if (codRecurso > 0) {
			recurso = recursoService.findOne(codRecurso);
			if(recurso == null) {
				flash.addFlashAttribute("error", "El codigo del recurso no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del recurso no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		model.put("recurso", recurso);
		model.put("titulo", "Historico de sueldos de " + recurso.getDescRecurso());
		return "listaSueldos";
	}
	
	@RequestMapping(value = "/formSueldo/{id}")
	public String editarSueldo(@PathVariable(value = "id") Long codSueldo, Map<String, Object> model, RedirectAttributes flash) {
		Sueldo sueldo= null;
		if (codSueldo > 0) {
			sueldo = sueldoService.findOne(codSueldo);
			if(sueldo == null) {
				flash.addFlashAttribute("error", "El codigo del sueldo no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del sueldo no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		model.put("sueldo", sueldo);
		model.put("titulo", "Formulario de sueldo");
		
		return "formSueldo";
	}
	
	@RequestMapping(value = "/asignarSueldo/{id}")
	public String crearSueldo(@PathVariable(value = "id") Long codRecurso, Map<String, Object> model, RedirectAttributes flash) {
		Recurso recurso = null;
		if (codRecurso > 0) {
			recurso = recursoService.findOne(codRecurso);
			if(recurso == null) {
				flash.addFlashAttribute("error", "El codigo del recurso no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del recurso no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		Sueldo sueldo= new Sueldo();
		sueldo.setRecurso(recurso);
		model.put("sueldo", sueldo);
		model.put("titulo", "Formulario de sueldo");
		
		return "formSueldo";
	}
	
	
	@RequestMapping(value="/formSueldo", method = RequestMethod.POST)
	public String guardarSueldo(@Valid Sueldo sueldo, BindingResult result, Model model,RedirectAttributes flash,SessionStatus status) {
		if(result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de sueldo");
			return "formSueldo";
		}
		sueldoService.save(sueldo);
		status.setComplete();
		flash.addFlashAttribute("success", "Sueldo guardado con éxito");
		return "redirect:listarSueldos/" + sueldo.getRecurso().getCodRecurso().toString();
	}
	
	@RequestMapping(value = "/borrarSueldo/{id}")
	public String borrarSueldo(@PathVariable(value = "id") Long codSueldo, Map<String, Object> model, RedirectAttributes flash) {
		Sueldo sueldo= null;
		if (codSueldo > 0) {
			sueldo = sueldoService.findOne(codSueldo);
			if(sueldo == null) {
				flash.addFlashAttribute("error", "El codigo del sueldo no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del sueldo no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		
		sueldoService.delete(sueldo);
		flash.addFlashAttribute("success", "Sueldo eliminado con éxito");
		return "redirect:../listarSueldos/" + sueldo.getRecurso().getCodRecurso().toString();
	}
	

}
