package com.sophi.app.controllers;

import java.util.Map;
import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.sophi.app.models.entity.Agenda;
import com.sophi.app.models.entity.Cargo;
import com.sophi.app.models.entity.Cliente;
import com.sophi.app.models.service.IAgendaService;
import com.sophi.app.models.service.ICargoService;
import com.sophi.app.models.service.IClienteService;
import com.sophi.app.models.service.IDetalleProyectoContactoService;

@Controller
@SessionAttributes("agenda")
public class AgendaController {
	
	@Autowired
	private IAgendaService agendaService;

	@Autowired
	private IClienteService clienteService;
	
	@Autowired
	private ICargoService cargoService;
	
	@Autowired
	private IDetalleProyectoContactoService detalleProyectoContactoService;

	
	@RequestMapping(value = "/agenda", method = RequestMethod.GET)
	public String Agenda(Model model) {
		List<Cliente> listaClientes = clienteService.findAll();
		Cliente cliente = clienteService.findOne(1L);
		listaClientes.remove(cliente);
		model.addAttribute("titulo", "Lista de Contactos");
		model.addAttribute("clientes", listaClientes);
		return "agenda";
	}
	
	@RequestMapping(value = "/contactos/{codCliente}", method = RequestMethod.GET)
	public String contactoListado(@PathVariable(value = "codCliente") Long codCliente,Model model) {
		List<Agenda> listaAgenda = new ArrayList<Agenda>();
		/*
		if (codCliente.equals(-1L)) {
			listaAgenda = agendaService.findAll();
		} else {
			listaAgenda = agendaService.findContactosBycodCliente(codCliente);
		}
		 */
		
		listaAgenda = agendaService.findContactosBycodCliente(codCliente);
		
		Agenda agenda = agendaService.findOne(1L);
		listaAgenda.remove(agenda);

		for (Agenda contacto : listaAgenda) {
			Long total = detalleProyectoContactoService.findTotalProyectosResponsable(contacto.getCodContacto());
			if(total.equals(0L)) {
				contacto.setEsBorrable(true);
			} else {
				contacto.setEsBorrable(false);
			}
		}
		
		model.addAttribute("contactos",listaAgenda);
		return "layout/plantilla-filtros :: contacto-listado";
	}
	
	@RequestMapping(value = "/dataContacto/{id}")
	public String verContacto(@PathVariable(value = "id") Long codContacto, Map<String, Object> model, RedirectAttributes flash) {
		Agenda agenda = null;
		if (codContacto > 0) {
			agenda = agendaService.findOne(codContacto);
			if(agenda == null) {
				flash.addFlashAttribute("error", "El codigo del contacto no existe en base de datos!");
				return "redirect:/agenda";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del contacto no debe ser cero!");
			return "redirect:/agenda";
		}
		agenda.setNombreCliente(clienteService.findOne(agenda.getCodCliente()).getDescCliente());
		agenda.setNombreCargo(cargoService.findOne(agenda.getCodCargo()).getDescCargo());
		model.put("agenda", agenda);
		model.put("textoTitulo","Información de tu contacto");
		model.put("textoDescriptivo","Encuentra aquí la información completa de tu contacto.");
		return "dataContacto";
	}
	
	@RequestMapping(value = "/newContacto/{codCliente}")
	public String crearContacto(Map<String, Object> model, @PathVariable(value = "codCliente") Long codcliente) {
		Agenda agenda = new Agenda();
		agenda.setValActivo(agenda.getValActivo() == null ? 1L : agenda.getValActivo());
		
		model.put("agenda", agenda);
		List<Cargo> cargoList = new ArrayList<Cargo>();
		List<Cliente> clienteList = new ArrayList<Cliente>();
		cargoList = cargoService.findAll();
		clienteList = clienteService.findAll();
		model.put("cargoList",cargoList);
		model.put("clienteList",clienteList);
		model.put("titulo", "Formulario de contactos");
		return "formContacto";
	}
	
	@RequestMapping(value="/formContacto", method = RequestMethod.POST)
	public String guardarContacto(@Valid Agenda agenda, Long codCliente, BindingResult result, Model model,RedirectAttributes flash,SessionStatus status) {
		if(result.hasErrors()) {
			model.addAttribute("titulo", "Formulario de contactos");
			List<Cargo> cargoList = new ArrayList<Cargo>();
			List<Cliente> clienteList = new ArrayList<Cliente>();
			cargoList = cargoService.findAll();
			clienteList = clienteService.findAll();
			model.addAttribute("cargoList",cargoList);
			model.addAttribute("clienteList",clienteList);
			return "formContacto";
		}
		if(agenda.getValActivo() == null) {
			agenda.setValActivo(1L);
		}
		agendaService.save(agenda);
		status.setComplete();
		flash.addFlashAttribute("success", "Contacto guardado con éxito");
		return "redirect:/dataCliente/"+codCliente;
	}
	
	@RequestMapping(value = "/formContacto/{id}")
	public String editarContacto(@PathVariable(value = "id") Long codContacto, Map<String, Object> model, RedirectAttributes flash) {
		Agenda agenda = null;
		if (codContacto > 0) {
			agenda = agendaService.findOne(codContacto);
			if(agenda == null) {
				flash.addFlashAttribute("error", "El codigo del contacto no existe en base de datos!");
				return "redirect:/agenda";
			} 
		} else {
			flash.addFlashAttribute("error", "El codigo del contacto no debe ser cero!");
			return "redirect:/agenda";
		}
		List<Cargo> cargoList = new ArrayList<Cargo>();
		List<Cliente> clienteList = new ArrayList<Cliente>();
		cargoList = cargoService.findAll();
		clienteList = clienteService.findAll();
		model.put("cargoList",cargoList);
		model.put("clienteList",clienteList);
		model.put("agenda", agenda);
		model.put("titulo", "Formulario contacto");
		return "formContacto";
	}
	
	@GetMapping(value = "/agenda/{id}")
	@ResponseBody
    public String eliminarContacto(@PathVariable(value = "id") Long codContacto, Model model) {
        System.out.println(codContacto);
		agendaService.delete(codContacto);
        return "1";
    }
	
}
