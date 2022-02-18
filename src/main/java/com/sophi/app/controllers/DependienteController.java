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

import com.sophi.app.models.entity.Dependiente;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.service.IDependienteService;
import com.sophi.app.models.service.IRecursoService;

@Controller
@SessionAttributes("dependiente")
public class DependienteController {
	
	@Autowired
	private IRecursoService recursoService;
	
	@Autowired
	private IDependienteService dependienteService;
	
	@RequestMapping(value = "/listarDependientes/{id}")
	public String listarDependientes(@PathVariable(value = "id") Long codRecurso, Map<String, Object> model, RedirectAttributes flash) {
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
		model.put("titulo", "Dependientes de " + recurso.getDescRecurso());
		return "listaDependientes";
	}
	
	@RequestMapping(value = "/formDependiente/{id}")
	public String editarDependiente(@PathVariable(value = "id") Long codDependiente, Map<String, Object> model, RedirectAttributes flash) {
		Dependiente dependiente= null;
		if (codDependiente > 0) {
			dependiente = dependienteService.findOne(codDependiente);
			if(dependiente == null) {
				flash.addFlashAttribute("error", "El codigo del dependiente no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del dependiente no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		model.put("dependiente", dependiente);
		model.put("titulo", "Formulario de dependientes");
		
		return "formDependiente";
	}
	
	@RequestMapping(value = "/asignarDependiente/{id}")
	public String crearDependiente(@PathVariable(value = "id") Long codRecurso, Map<String, Object> model, RedirectAttributes flash) {
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
		Dependiente dependiente= new Dependiente();
		dependiente.setRecurso(recurso);
		model.put("dependiente", dependiente);
		model.put("titulo", "Formulario de dependientes");
		
		return "formDependiente";
	}
	
	
	@RequestMapping(value="/formDependiente", method = RequestMethod.POST)
	public String guardarDependiente(@Valid Dependiente dependiente, BindingResult result, Model model,RedirectAttributes flash,SessionStatus status) {
		if(result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de dependientes");
			return "formDependiente";
		}
		dependienteService.save(dependiente);
		status.setComplete();
		flash.addFlashAttribute("success", "Dependiente guardado con éxito");
		return "redirect:listarDependientes/" + dependiente.getRecurso().getCodRecurso().toString();
	}
	
	@RequestMapping(value = "/borrarDependiente/{id}")
	public String borrarDependiente(@PathVariable(value = "id") Long codDependiente, Map<String, Object> model, RedirectAttributes flash) {
		Dependiente dependiente= null;
		if (codDependiente > 0) {
			dependiente = dependienteService.findOne(codDependiente);
			if(dependiente == null) {
				flash.addFlashAttribute("error", "El codigo del dependiente no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del dependiente no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		
		dependienteService.delete(dependiente);
		flash.addFlashAttribute("success", "Dependiente eliminado con éxito");
		return "redirect:../listarDependientes/" + dependiente.getRecurso().getCodRecurso().toString();
	}
	

}
