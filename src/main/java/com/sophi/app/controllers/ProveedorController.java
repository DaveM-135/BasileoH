package com.sophi.app.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.sophi.app.models.entity.Proveedor;
import com.sophi.app.models.service.IProveedorService;


@Controller
@SessionAttributes("proveedor")
public class ProveedorController {
	
	@Autowired
	private IProveedorService proveedorService;
	
	@GetMapping(value = "/formProveedor")
	public String crearProveedor(Model model) {	
		Proveedor proveedor = new Proveedor();
		model.addAttribute("proveedor", proveedor);
		return "formProveedor";
	}
	
	@RequestMapping(value="/formProveedor", method = RequestMethod.POST)
	public String guardarProveedor(@Valid Proveedor proveedor, BindingResult result, Model model, RedirectAttributes flash,SessionStatus status) {
		if(result.hasErrors()) {
			model.addAttribute("titulo", "Formulario proveedores");
			return "formProveedor";
		}
		String mensajeFlash = (proveedor.getCodProveedor() != null)?"Proveedor editado con éxito!": "Proveedor guardado con éxito";
		
		proveedorService.save(proveedor);
		status.setComplete();
		flash.addFlashAttribute("success", mensajeFlash);
		
	return "redirect:/listarProveedores";
	}
	
	@GetMapping(value = "/listarProveedores")
	public String listarProveedores(Map<String, Object> model, RedirectAttributes flash) {
		List<Proveedor> proveedores = new ArrayList<Proveedor>();
		proveedores = proveedorService.findAll();
		model.put("proveedores", proveedores);
		model.put("titulo", "Listado de proveedores");
		return "listaProveedores";
	}
	
	@GetMapping(value = "/formProveedor/{id}")
	public String editaProveedor(@PathVariable(value = "id") Long codProveedor, Map<String, Object> model, RedirectAttributes flash) {
		Proveedor proveedor= null;
		if (codProveedor > 0) {
			proveedor = proveedorService.findOne(codProveedor);
			if(proveedor == null) {
				flash.addFlashAttribute("error", "El codigo del proveedor no existe en base de datos!");
				return "redirect:/listarProveedores";
			}
		} else {
			flash.addFlashAttribute("error", "El codigo del proveedor no debe ser cero!");
			return "redirect:/listarProveedores";
		}
		model.put("proveedor", proveedor);
		model.put("titulo", "Datos del proveedor");
		return "formProveedor";
	}

}
