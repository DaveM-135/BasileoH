package com.sophi.app.controllers;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.sophi.app.Utiles;
import com.sophi.app.models.entity.PreguntaClima;
import com.sophi.app.models.entity.PreguntaRespuestaClima;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RespuestaFlash;
import com.sophi.app.models.entity.RespuestaRecursoClima;
import com.sophi.app.models.service.IPreguntaClimaService;
import com.sophi.app.models.service.IPreguntaRespuestaClimaService;
import com.sophi.app.models.service.IRecursoService;
import com.sophi.app.models.service.IRespuestaFlashService;
import com.sophi.app.models.service.IRespuestaRecursoClimaService;

@Controller
public class FlashController {
	
	@Autowired
	private IRecursoService recursoService;
	
	@Autowired
	private IPreguntaClimaService preguntaClimaService;
	
	@Autowired
	private IRespuestaFlashService respuestaFlashService;
	
	@Autowired
	private IPreguntaRespuestaClimaService preguntaRespuestaClimaService;
	
	@Autowired
	private IRespuestaRecursoClimaService respuestaRecursoClimaService;
	
	@RequestMapping(value = "/guardaRespuestaFlash")
	@ResponseBody
	public String guardaRespuestaFlash(@RequestParam String recurso, @RequestParam Long respuesta, @RequestParam Long pregunta,Model model) {
		Recurso recursoRes = recursoService.findByDescCorreoElectronico(recurso);
		RespuestaRecursoClima respuestaRecurso = new RespuestaRecursoClima();
		
		System.out.println(respuesta);
		
		respuestaRecurso.setCodPreguntaRespuesta(preguntaRespuestaClimaService.findOne(respuesta).getValRespuesta());
		respuestaRecurso.setRecurso(recursoRes);
		respuestaRecurso.setCodPreguntaClima(pregunta);
		
		respuestaRecursoClimaService.save(respuestaRecurso);
		return "Gracias";
	} 
	
	@RequestMapping(value = "/guardaPreguntaFlash")
	@ResponseBody
	public String guardaPreguntaFlash(@RequestParam String pregunta, @RequestParam String respuestas, Model model) {
		System.out.println(pregunta + "  " +  respuestas);
		
		PreguntaClima preguntaClima = preguntaClimaService.findOne(1L);
		preguntaClima.setDescPreguntaClima(pregunta);
		preguntaClima.setValTipo(1L);
		preguntaClimaService.save(preguntaClima);
		
		if(respuestas != null) {
			String[] listRespuestas = respuestas.split(",");
			if (listRespuestas.length > 0) {
				//Borran respuestas actuales
				List<PreguntaRespuestaClima> listaRespuestasActuales =  preguntaRespuestaClimaService.findByCodPregunta(1L);
				for (PreguntaRespuestaClima preguntaRespuestaClima : listaRespuestasActuales) {
					preguntaRespuestaClimaService.delete(preguntaRespuestaClima.getCodPreguntaRespuestaClima());
				}
				for (String codRespuesta : listRespuestas) {
					PreguntaRespuestaClima prc = new PreguntaRespuestaClima();
					prc.setPreguntaClima(preguntaClimaService.findOne(1L));
					RespuestaFlash respuestaFlash = respuestaFlashService.findByCodRespuesta(Long.parseLong(codRespuesta));
					prc.setValRespuesta(respuestaFlash.getCodRespuesta());
					prc.setValImagenRespuesta(respuestaFlash.getRutaImagen());
					preguntaRespuestaClimaService.save(prc);
				}
			}
		}
		
		return "1";
	} 
	
	
	@RequestMapping(value = "/guardaPreguntaFlashSemanal")
	@ResponseBody
	public String guardaPreguntaFlashSemanal(@RequestParam String pregunta, @RequestParam String respuestas, Model model) {
		System.out.println(pregunta + "  " +  respuestas);
		
		PreguntaClima preguntaClima = preguntaClimaService.findOne(2L);
		preguntaClima.setDescPreguntaClima(pregunta);
		preguntaClimaService.save(preguntaClima);
		
		if(respuestas != null) {
			String[] listRespuestas = respuestas.split(",");
			if (listRespuestas.length > 0) {
				//Borran respuestas actuales
				List<PreguntaRespuestaClima> listaRespuestasActuales =  preguntaRespuestaClimaService.findByCodPregunta(2L);
				for (PreguntaRespuestaClima preguntaRespuestaClima : listaRespuestasActuales) {
					preguntaRespuestaClimaService.delete(preguntaRespuestaClima.getCodPreguntaRespuestaClima());
				}
				for (String codRespuesta : listRespuestas) {
					PreguntaRespuestaClima prc = new PreguntaRespuestaClima();
					prc.setPreguntaClima(preguntaClimaService.findOne(2L));
					RespuestaFlash respuestaFlash = respuestaFlashService.findByCodRespuesta(Long.parseLong(codRespuesta));
					prc.setValRespuesta(respuestaFlash.getCodRespuesta());
					prc.setValImagenRespuesta(respuestaFlash.getRutaImagen());
					preguntaRespuestaClimaService.save(prc);
				}
			}
		}
		
		return "1";
	} 
	
	@GetMapping(value="/datosRecursoLoginFlash/{login}")
	public String cargarDatosRecursoLoginFlash(@PathVariable String login, Model model){
		recursoService.findByDescCorreoElectronico(login);
		model.addAttribute("recursoFlash", recursoService.findByDescCorreoElectronico(login));
		
		int diaSemana = 0;
		Date fechaHoy = new Utiles().getFechaActual();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(fechaHoy);
		
		diaSemana = calendar.get(Calendar.DAY_OF_WEEK);
		if(diaSemana == 6) {
			PreguntaClima pC1 = preguntaClimaService.findOne(1L);
			model.addAttribute("preguntaFlash",pC1);
			model.addAttribute("pregunta", 1);
			model.addAttribute("respuestasFlash",preguntaRespuestaClimaService.findByCodPregunta(1L));
			
		} else {
			PreguntaClima pC2 = preguntaClimaService.findOne(2L);
			model.addAttribute("preguntaFlash", pC2);
			model.addAttribute("pregunta", 2);
			model.addAttribute("respuestasFlash",preguntaRespuestaClimaService.findByCodPregunta(2L));
		}
		
		
		return "layout/layout :: modalFlash";
	}
	
	@RequestMapping(value = "/validaRespuestaFlash")
	@ResponseBody
	public String validaRespuestaFlash(@RequestParam String recurso,Model model) {
		Recurso recursoRes = recursoService.findByDescCorreoElectronico(recurso);
		List<RespuestaRecursoClima> listadoRespuesta = respuestaRecursoClimaService.findByRecurso(recursoRes);
		if (listadoRespuesta.size() > 0) {
			return "0";
		} else {
			int diaSemana = 0;
			Date fechaHoy = new Utiles().getFechaActual();
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(fechaHoy);
			
			diaSemana = calendar.get(Calendar.DAY_OF_WEEK);
			if(diaSemana == 6) {
				PreguntaClima pC1 = preguntaClimaService.findOne(1L);
				if (pC1.isValActivo()) {
					return "1";
				} else {
					return "0";
				}
			} else {
				PreguntaClima pC2 = preguntaClimaService.findOne(2L);
				if (pC2.isValActivo()) {
					return "1";
				} else {
					return "0";
				}
			}
			
		}
	} 
	
	@RequestMapping(value = "/flashClima")
	public String flashClima(Model model) {
		model.addAttribute("preguntaFlash", preguntaClimaService.findOne(1L));
		model.addAttribute("respuestasPreguntaFlash", preguntaRespuestaClimaService.findByCodPregunta(1L));
		model.addAttribute("preguntaFlashSemanal",preguntaClimaService.findOne(2L));
		model.addAttribute("respuestasPreguntaFlashSemanal", preguntaRespuestaClimaService.findByCodPregunta(2L));
		model.addAttribute("catRespuestas",respuestaFlashService.findAll());
		return "clima";
	} 
	
	@RequestMapping(value = "/activarEncuestaFlash")
	@ResponseBody
	public String activarEncuestaFlash(@RequestParam Long idEncuesta,@RequestParam Boolean valActivo) {
		PreguntaClima preguntaClima = preguntaClimaService.findOne(idEncuesta);
		preguntaClima.setValActivo(valActivo);
		try {
			preguntaClimaService.save(preguntaClima);
			return "1";
		} catch (Exception e) {
			return "0";
		}
	} 
	
	
	
	

}
