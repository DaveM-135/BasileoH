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

import com.sophi.app.Utiles;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.Skill;
import com.sophi.app.models.service.IRecursoService;
import com.sophi.app.models.service.ISkillService;

@Controller
@SessionAttributes("skill")
public class SkillController {
	
	@Autowired
	private IRecursoService recursoService;
	
	@Autowired
	private ISkillService skillService;
	
	@RequestMapping(value = "/listarSkill/{id}")
	public String listarSkill(@PathVariable(value = "id") Long codRecurso, Map<String, Object> model, RedirectAttributes flash) {
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
		model.put("titulo", "Skills de " + recurso.getDescRecurso());
		return "listaSkill";
	}
	
	@RequestMapping(value = "/formSkill/{id}")
	public String editarSkill(@PathVariable(value = "id") Long codSkill, Map<String, Object> model, RedirectAttributes flash) {
		Skill skill= null;
		if (codSkill > 0) {
			skill = skillService.findOne(codSkill);
			if(skill == null) {
				flash.addFlashAttribute("error", "El codigo del skill no existe en base de datos!");
				return "redirect:/listarRecursos";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del skill no debe ser cero!");
			return "redirect:/listarRecursos";
		}
		Utiles utiles = new Utiles();
		model.put("skillTipoList",utiles.skillTipoList());
		model.put("skillDominioList",utiles.skillDominioList());
		model.put("skill", skill);
		model.put("titulo", "Formulario de skills");
		
		return "formSkill";
	}
	
	@RequestMapping(value = "/asignarSkill/{id}")
	public String crearSkill(@PathVariable(value = "id") Long codRecurso, Map<String, Object> model, RedirectAttributes flash) {
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
		Skill skill = new Skill();
		skill.setRecurso(recurso);
		Utiles utiles = new Utiles();
		model.put("skillTipoList",utiles.skillTipoList());
		model.put("skillDominioList",utiles.skillDominioList());
		model.put("skill", skill);
		model.put("titulo", "Formulario de herramientas");
		
		return "formSkill";
	}
	
	
	@RequestMapping(value="/formSkill", method = RequestMethod.POST)
	public String guardarSkill(@Valid Skill skill, BindingResult result, Model model,RedirectAttributes flash,SessionStatus status) {
		if(result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de Skills");
			Utiles utiles = new Utiles();
			model.addAttribute("skillTipoList",utiles.skillTipoList());
			model.addAttribute("skillDominioList",utiles.skillDominioList());
			return "formSkill";
		}
		skillService.save(skill);
		status.setComplete();
		flash.addFlashAttribute("success", "Skill guardado con éxito");
		return "redirect:listarSkill/" + skill.getRecurso().getCodRecurso().toString();
	}
	
	@RequestMapping(value = "/borrarSkill/{id}")
	public String borrarSkill(@PathVariable(value = "id") Long codSkill, Map<String, Object> model, RedirectAttributes flash) {
		Skill skill= null;
		if (codSkill> 0) {
			skill = skillService.findOne(codSkill);
			if(skill == null) {
				flash.addFlashAttribute("error", "El codigo del skill no existe en base de datos!");
				return "redirect:/listarSkill";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del skill no debe ser cero!");
			return "redirect:/listarSkill";
		}
		
		skillService.delete(skill);
		flash.addFlashAttribute("success", "Skill eliminado con éxito");
		return "redirect:../listarSkill/" + skill.getRecurso().getCodRecurso().toString();
	}

}
