package com.sophi.app.controllers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.sophi.app.models.entity.Actividad;
import com.sophi.app.models.entity.Proyecto;
import com.sophi.app.models.service.IActividadService;
import com.sophi.app.models.service.IProyectoService;
import com.sophi.app.models.service.IRecursoService;

@Controller
//@SessionAttributes("capHora")
public class ActividadesRecursoController {
	
	@Autowired
	private IActividadService actividadService;
	
	@Autowired
	private IRecursoService recursoService;
	
	@Autowired
	private IProyectoService proyectoService;
	
	@GetMapping("/misActividades/{email}")
	public String capHoras(@PathVariable(value="email") String email, Model model) {
		Long codRecurso = recursoService.findByDescCorreoElectronico(email).getCodRecurso();
//		List<Actividad> listaActividades =  actividadService.findByCodRecurso(codRecurso);
		List<Actividad> listaActividades = new ArrayList<Actividad>();
		
		HashMap<Long, String> proyectoList = new HashMap<Long, String>(); 
		
		List<Long> listadoDeProyectos = new ArrayList<Long>();
		listadoDeProyectos = actividadService.findListaProyectoByRecurso(codRecurso);
		
		//Solo proyectos Activos
		for (Long id : listadoDeProyectos) {
			Proyecto proyecto = proyectoService.findOne(id);
			if (proyecto.getCodEstatusProyecto().equals(1L) || proyecto.getCodEstatusProyecto().equals(2L)) {
				proyectoList.put(id,proyecto.getDescProyecto());
				listaActividades.addAll(actividadService.findListaActividadesByRecursoProyecto(codRecurso, id));
			}
		}
		
		for (Actividad actividad : listaActividades) {
			for (Map.Entry<Long, String> entry : proyectoList.entrySet()) {
			    if (actividad.getCodProyecto().equals(entry.getKey())) {
			    	actividad.setNombreProyecto(entry.getValue());
			    	break;
			    }
			}
		}
		
		
		model.addAttribute("listaActividades", listaActividades);
		model.addAttribute("proyectos", proyectoList);
		model.addAttribute("codRecurso", codRecurso);
		return "listaActividadesRecurso";
	}
	
	
	@GetMapping("/misActividadesProyecto/{email}/{codProyecto}")
	public String capHoras(@PathVariable(value="email") String email, @PathVariable(value="codProyecto") Long codProyecto, Model model) {
		Long codRecurso = recursoService.findByDescCorreoElectronico(email).getCodRecurso();
		List<Actividad> listaActividades = new ArrayList<Actividad>();
		
		if (codProyecto.equals(-1L)) {
			HashMap<Long, String> proyectoList = new HashMap<Long, String>(); 
			
			List<Long> listadoDeProyectos = new ArrayList<Long>();
			listadoDeProyectos = actividadService.findListaProyectoByRecurso(codRecurso);
			
			//Solo proyectos Activos
			for (Long id : listadoDeProyectos) {
				Proyecto proyecto = proyectoService.findOne(id);
				if (proyecto.getCodEstatusProyecto().equals(1L) || proyecto.getCodEstatusProyecto().equals(2L)) {
					proyectoList.put(id,proyecto.getDescProyecto());
					listaActividades.addAll(actividadService.findListaActividadesByRecursoProyecto(codRecurso, id));
				}
			}
			
			for (Actividad actividad : listaActividades) {
				for (Map.Entry<Long, String> entry : proyectoList.entrySet()) {
				    if (actividad.getCodProyecto().equals(entry.getKey())) {
				    	actividad.setNombreProyecto(entry.getValue());
				    	break;
				    }
				}
			}
		} else {
			
			HashMap<Long, String> proyectoList = new HashMap<Long, String>(); 
			Proyecto proyecto = proyectoService.findOne(codProyecto);
			if (proyecto.getCodEstatusProyecto().equals(1L) || proyecto.getCodEstatusProyecto().equals(2L)) {
				proyectoList.put(codProyecto,proyecto.getDescProyecto());
				listaActividades = actividadService.findListaActividadesByRecursoProyecto(codRecurso, codProyecto);
			}
			
			
			
			for (Actividad actividad : listaActividades) {
				for (Map.Entry<Long, String> entry : proyectoList.entrySet()) {
				    if (actividad.getCodProyecto().equals(entry.getKey())) {
				    	actividad.setNombreProyecto(entry.getValue());
				    	break;
				    }
				}
			}
			
		}
		
		model.addAttribute("listaActividades", listaActividades);
		
		return "layout/plantilla-filtros :: actividades-listado";
	}
}
