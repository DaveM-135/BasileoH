package com.sophi.app.controllers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sophi.app.mail.dto.MailRequest;
import com.sophi.app.mail.dto.MailResponse;
import com.sophi.app.mail.service.EmailService;
import com.sophi.app.models.entity.AprobacionGastos;
import com.sophi.app.models.entity.AprobacionGastosDto;
import com.sophi.app.models.entity.Proyecto;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.Rol;
import com.sophi.app.models.service.IAprobacionGastosService;
import com.sophi.app.models.service.IProyectoService;
import com.sophi.app.models.service.IRecursoService;
import com.sophi.app.models.service.IRolService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@SessionAttributes("aprobaciongastoslista")
public class AprobacionGastosController {

	@Autowired
	private EmailService service;
	
	@Autowired
    private IAprobacionGastosService aprobaciongastosService;

    @Autowired
    private IRecursoService recursoService;
    
    @Autowired
    private IProyectoService proyectoService;
    
    @Autowired
    private IRolService rolService;
    
    public Long CodRecurso;

    @RequestMapping(value = "/aprobaciongastos/{email}", method = RequestMethod.GET)
    public String AprobacionGastos(Model model, @PathVariable(value = "email") String email) {
    	
    	Long codRecurso = recursoService.findByDescCorreoElectronico(email).getCodRecurso();
    	int esAdmin = 0;
    	int esAprob = 0;
    	 
    	for (Rol rol : rolService.findByCodRecurso(codRecurso)) {
			if(rol.getDescRol().equalsIgnoreCase("ROLE_ADMIN")) {
				esAdmin = 1;
				System.out.println(rol.getDescRol());
			} else if(rol.getDescRol().equalsIgnoreCase("ROLE_APROB")) {
				esAprob = 1;
				System.out.println(rol.getDescRol());
			}
		} 
    	 
    	AprobacionGastosDto apgdto = new AprobacionGastosDto();
    	 //Declaracion de listas e inicializacion
    	List<AprobacionGastos> aprobacionesgastos = new ArrayList<AprobacionGastos>();
    	List<Recurso> listaRecursos = new ArrayList<Recurso>();
		List<Proyecto> listaProyectosTmp = new ArrayList<Proyecto>();
		List<Proyecto> listaProyectos = new ArrayList<Proyecto>();
    	 
	if (esAdmin == 1) {

		//Obtencion de proyectos activos del recurso aprobador
		listaProyectosTmp = proyectoService.findAll();
	 
		for (Proyecto proyecto : listaProyectosTmp) {
			if (proyecto.getCodEstatusProyecto().equals(2L) || proyecto.getCodEstatusProyecto().equals(1L)) {
				listaProyectos.add(proyecto);
				aprobacionesgastos.addAll(aprobaciongastosService.findAprobacionGastosBycodProyecto(proyecto.getCodProyecto()));
			}
		}
	 
		listaRecursos = recursoService.findRecursosActivos();
	 
		apgdto.setAprobaciongastos(aprobacionesgastos);
	} else if (esAprob == 1) {
		listaProyectosTmp = proyectoService.findListaProyectosRecursoAprobadorTodos(codRecurso);
		
		for (Proyecto proyecto : listaProyectosTmp) {
			
			if(proyecto.getCodEstatusProyecto().equals(2L) || proyecto.getCodEstatusProyecto().equals(1L)) {
				listaProyectos.add(proyecto);
				aprobacionesgastos.addAll(aprobaciongastosService.findAprobacionGastosBycodProyecto(proyecto.getCodProyecto()));
			}
		}
	 
		listaRecursos = recursoService.findRecursosActivos();
	 
		apgdto.setAprobaciongastos(aprobacionesgastos);
	}
	
	for (AprobacionGastos apgas : apgdto.getAprobaciongastos()) {
		System.out.println(apgas.getDescComentario());
		System.out.println(apgas.getValGastoPlaneado());
	}
    	 
    	 model.addAttribute("aprobaciongastoslista",apgdto);
    	 model.addAttribute("proyectos", listaProyectos);
    	 model.addAttribute("recursos", listaRecursos);
    	 model.addAttribute("r", codRecurso);
    	 CodRecurso = codRecurso;
    	 
    	 return "aprobaciongastos";
	}
    
    
    @RequestMapping(value = "/aprobacionGastosProyecto/{codProyecto}", method = RequestMethod.GET)
    public String AprobacionGastosProyecto(@PathVariable(value = "codProyecto") String codProyecto, Model model) {
 
		//Declaracion de listas e inicializacion
		List<AprobacionGastos> aprobacionesgastos = new ArrayList<AprobacionGastos>();
		
		String[] proyectos = codProyecto.split(",");
		
		for (String cod : proyectos) {
			if (cod.equalsIgnoreCase("-1")) {
				continue;
			} else {
				aprobacionesgastos.addAll(aprobaciongastosService.findAprobacionGastosBycodProyecto(Long.parseLong(cod)));
			}
		}
			
		AprobacionGastosDto apgdto = new AprobacionGastosDto();
		apgdto.setAprobaciongastos(aprobacionesgastos);
		 
		model.addAttribute("aprobaciongastoslista",apgdto);
		 
		return "layout/plantilla-filtros :: gastos-listado";
	}
    
    
    @RequestMapping(value="/validar", method = RequestMethod.POST)
    public String validarGastos(@ModelAttribute("aprobaciongastoslista") AprobacionGastosDto aprobaciongastoslista, BindingResult result, Model model,RedirectAttributes flash,SessionStatus status) {
    	if(result.hasErrors()) {
			model.addAttribute("titulo", "Listado Gastos Capturados");
			List<Recurso> listaRecursos = new ArrayList<Recurso>();
	        listaRecursos = recursoService.findAll();
	        model.addAttribute("recursos", listaRecursos);	        
	        model.addAttribute("r", CodRecurso);
			return "aprobaciongastos";
		}
    	
    	List<AprobacionGastos> listaAprobacion = new ArrayList<AprobacionGastos>();
    	listaAprobacion = aprobaciongastoslista.getAprobaciongastos();
    	for (AprobacionGastos aprobacionGastos : listaAprobacion) {
    		aprobaciongastosService.updateValidacion(aprobacionGastos.getCodRecursoValidador(), aprobacionGastos.getFecValidacion(), aprobacionGastos.getValImporteValidado(), aprobacionGastos.getValGastoPlaneado(),  aprobacionGastos.getCodRecursoGasto());
    		try {
    			enviaNotificacionAprobacionGastoAlRecurso(aprobacionGastos);
			} catch (Exception e) {
				System.out.println("NOTIFICACIONES : <Error> No se puede enviar notificacion al recurso de su gasto aprobado.");
			}
    	}
    	
		status.setComplete();
		flash.addFlashAttribute("success", "Gastos aprobados");
		return "redirect:/aprobaciongastos/"+recursoService.findOne(CodRecurso).getDescCorreoElectronico();
    }
    
    
    //Notificar al recurso del estatus de aprobacion 
  	public void enviaNotificacionAprobacionGastoAlRecurso(AprobacionGastos recursoGastos) {

  		Recurso recurso = recursoService.findOne(recursoGastos.getCodRecurso());
  		
  		MailRequest request = new MailRequest();
  		request.setName(recurso.getDescRecurso());
  		request.setSubject("Estatus del gasto reportado");
  		request.setTo(recurso.getDescCorreoElectronico());
  		
  		Map<String, Object> model = new HashMap<String, Object>();
  		model.put("nombreRecurso", request.getName());
  		model.put("mensaje", "<h3>Tu gasto \""+ recursoGastos.getDescComentario() +"\" tiene un nuevo estatus, consultalo en la plataforma.</h3>");
  		model.put("imagen","<img data-cfsrc=\"images/status.png\" alt=\"\" data-cfstyle=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" style=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" src=\"https://sophitech.herokuapp.com/img/img-status.png\">");
  		model.put("pie", "");
  		
  		MailResponse response = service.sendEmail(request, model);
  		System.out.println(response.getMessage());
  	}
  	

    
}