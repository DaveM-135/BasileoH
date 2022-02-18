package com.sophi.app.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.sophi.app.models.entity.Competencias;
import com.sophi.app.models.entity.CompetenciasPerfiles;
import com.sophi.app.models.entity.Metas;
import com.sophi.app.models.entity.MetasPerfiles;
import com.sophi.app.models.entity.PerfilRecurso;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.service.ICompetenciaService;
import com.sophi.app.models.service.ICompetenciasPerfilesService;
import com.sophi.app.models.service.IMetasPerfilesService;
import com.sophi.app.models.service.IMetasService;
import com.sophi.app.models.service.IPerfilRecursoService;
import com.sophi.app.models.service.IRecursoService;

@Controller
public class PerfilController {
	
	@Autowired
	private IPerfilRecursoService perfilRecursoService;
	
	@Autowired
	private ICompetenciaService competenciaService;
	
	@Autowired
	private IMetasService metaService;
	
	@Autowired
	private ICompetenciasPerfilesService competenciaPerfilService;
	
	@Autowired
	private IMetasPerfilesService metaPerfilService;
	
	@Autowired
	private IRecursoService recursoService;
	
	@RequestMapping(value = "/perfiles")
	public String verPerfiles(Map<String, Object> model) {
		
		List<PerfilRecurso> listaPerfiles = perfilRecursoService.findAll();
		for (PerfilRecurso perfilRecurso : listaPerfiles) {
			perfilRecurso.setTotalRecursosAsignados(perfilRecursoService.totalRecursosAsignados(perfilRecurso.getCodPerfil()));
		}
		model.put("listaPerfiles", listaPerfiles);
		return "listaPerfiles";
	} 
	
	@RequestMapping(value = "/getMetasCompetencias")
	public String verMetasCompetencias(@RequestParam("c") Long codPerfil, Map<String, Object> model) {
		PerfilRecurso perfil = perfilRecursoService.findByCodPerfil(codPerfil);
		model.put("perfil", perfil);
		return "layout/plantilla-perfiles :: modalMetasCompetencias";
	} 
	
	
	@RequestMapping(value = "/formPerfil")
	public String nuevoPerfil(Map<String, Object> model) {
		PerfilRecurso perfil = new PerfilRecurso();
		model.put("perfil", perfil);
		model.put("titulo", "Nuevo perfil");
		return "layout/plantilla-perfiles :: modalperfil";
	}
	
	@RequestMapping(value = "/editarPerfil")
	public String editarPerfil(@RequestParam("c") Long codPerfil, Map<String, Object> model) {
		PerfilRecurso perfil = perfilRecursoService.findByCodPerfil(codPerfil);
		model.put("perfil", perfil);
		model.put("titulo", "Editar perfil");
		return "layout/plantilla-perfiles :: modalperfil";
	}
	
	
	@RequestMapping(value = "/getMetasEditar")
	@ResponseBody
	public String metasEditar(@RequestParam("c") Long codPerfil, Map<String, Object> model) {
		PerfilRecurso perfil = perfilRecursoService.findByCodPerfil(codPerfil);
		StringBuilder metas = new StringBuilder();
		for (MetasPerfiles metaPerfil : perfil.getMetasPerfiles()) {
			metas.append("<tr>");
			metas.append("<td class='d-none'><input type='hidden' value='1' name='banderaMeta[]'</td>");
			metas.append("<td class='d-none'><input type='hidden' value='"+ metaPerfil.getMeta().getDescMeta() +"' name='nombreMeta[]'</td>");
			metas.append("<td class='d-none'><input type='hidden' value='"+ metaPerfil.getMeta().getDescDefinicion()+"' name='definicionMeta[]'</td>");
			metas.append("<td style='vertical-align: middle; font-size: 12px; padding: 5px;'>" + metaPerfil.getMeta().getDescMeta() + "</td>");
			metas.append("<td style='vertical-align: middle; font-size: 12px; padding: 5px; width: 100px;'><input type='text' name='porcentajeMeta[]' onkeypress='return event.charCode >= 48 && event.charCode <= 57'  onkeyup='validarPorcentaje();' value='" +metaPerfil.getValPorcentaje() +"' class='form-control inputPerfil'></td>");
			metas.append("<td style='vertical-align: middle; font-size: 12px; padding: 5px; width: 30px;'><i class='fas fa-trash-alt borrarMeta' style='cursor: pointer;' onclick='borrarMeta(this);'></i></td>");
			metas.append("</tr>");
		}
		return metas.toString();
	}
	
	@RequestMapping(value = "/getCompetenciasEditar")
	@ResponseBody
	public String competenciasEditar(@RequestParam("c") Long codPerfil, Map<String, Object> model) {
		PerfilRecurso perfil = perfilRecursoService.findByCodPerfil(codPerfil);
		StringBuilder competencias = new StringBuilder();
		for (CompetenciasPerfiles competenciaPerfil : perfil.getCompetenciasPerfiles()) {
			competencias.append("<tr>" );
			competencias.append("<td class='d-none'><input type='hidden' value='1' name='banderaCompetencia[]'</td>");
			competencias.append("<td class='d-none'><input type='hidden' value='"+ competenciaPerfil.getCompetencia().getDescCompetencias()+"' name='nombreCompetencia[]'</td>");
			competencias.append("<td class='d-none'><input type='hidden' value='"+ competenciaPerfil.getCompetencia().getDescDefinicion()+"' name='definicionCompetencia[]'</td>");
			competencias.append("<td style='vertical-align: middle; font-size: 12px; padding: 5px;'>" + competenciaPerfil.getCompetencia().getDescCompetencias() + "</td>");
			competencias.append("<td style='vertical-align: middle; font-size: 12px; padding: 5px;'><textarea  class='form-control inputPerfil' name='reactivoCompetencia[]'>" + competenciaPerfil.getDescDefinicion()+ "</textarea></td>");
			competencias.append("<td style='vertical-align: middle; font-size: 12px; padding: 5px;'><i class='fas fa-trash-alt borrarMeta' style='cursor: pointer;' onclick='borrarCompetencia(this);'></i></td>");
			competencias.append("</tr>");
		}
		
		return competencias.toString();
	}
	
	
	
	@RequestMapping(value = "/getCompetencias")
	public String listadoCompetencias(Map<String, Object> model) {
		List<Competencias> listaCompetencias = competenciaService.findAll();
		model.put("listaCompetencias", listaCompetencias);
		model.put("definicion", listaCompetencias.get(0).getDescDefinicion());
		return "layout/plantilla-perfiles :: modalCompetencias";
	}
	
	@RequestMapping(value = "/getDefinicionCompetencia")
	@ResponseBody
	public String definicionComptencia(@RequestParam("c") Long codCompetencia, Map<String, Object> model) {
		Competencias competencia = competenciaService.findById(codCompetencia);
		String definicion = "";
		if(competencia != null) {
			definicion = competencia.getDescDefinicion();
		}
		return definicion;
	}
	
	
	@RequestMapping(value = "/getMetas")
	public String listadoMetas(Map<String, Object> model) {
		List<Metas> listaMetas = metaService.findAll();
		model.put("listaMetas", listaMetas);
		model.put("definicionMeta", listaMetas.get(0).getDescDefinicion());
		return "layout/plantilla-perfiles :: modalMetas";
	}
	
	@RequestMapping(value = "/getDefinicionMeta")
	@ResponseBody
	public String definicionMeta(@RequestParam("c") Long codMeta, Map<String, Object> model) {
		Metas meta = metaService.findById(codMeta);
		String definicionMeta = "";
		if(meta != null) {
			definicionMeta = meta.getDescDefinicion();
		}
		return definicionMeta;
	}
	
	@PostMapping(value = "/formPerfil")
	public String guardaPerfil(PerfilRecurso perfil, 
			@RequestParam(name="banderaMeta[]",required = false) String[] banderaMeta, 
			@RequestParam(name="nombreMeta[]",required = false) String[] nombreMeta,
			@RequestParam(name="definicionMeta[]",required = false) String[] definicionMeta,
			@RequestParam(name="porcentajeMeta[]",required = false) Long[] porcentajeMeta,
			@RequestParam(name="banderaCompetencia[]",required = false) String[] banderaCompetencia, 
			@RequestParam(name="nombreCompetencia[]",required = false) String[] nombreCompetencia,
			@RequestParam(name="definicionCompetencia[]",required = false) String[] definicionCompetencia,
			@RequestParam(name="reactivoCompetencia[]",required = false) String[] reactivoCompetencia
			) {
		
		perfilRecursoService.guardar(perfil);
		
		if (perfil.getCodPerfil() != null) {
			competenciaPerfilService.deleteByCodPerfil(perfil.getCodPerfil());
			metaPerfilService.deleteByCodPerfil(perfil.getCodPerfil());
		}
		
		List<MetasPerfiles> ListaMetasPerfiles = new ArrayList<MetasPerfiles>();
		
		for (int i = 0; i < banderaMeta.length; i++) {
			
			Metas meta = null;
			
			if(banderaMeta[i].equals("1")) {
				meta = metaService.findByDescMeta(nombreMeta[i].trim());
			} else if(banderaMeta[i].equals("2")) {
				meta = new Metas();
				meta.setDescMeta(nombreMeta[i].trim());
				meta.setDescDefinicion(definicionMeta[i].trim());
				metaService.guardar(meta);
			}
			
			MetasPerfiles mp = new MetasPerfiles();
			mp.setPerfil(perfil);
			mp.setMeta(meta);
			mp.setValPorcentaje(porcentajeMeta[i]);
			
			ListaMetasPerfiles.add(mp);
		}
		
		metaPerfilService.guardarAll(ListaMetasPerfiles);
		
		
		
		List<CompetenciasPerfiles> listaCompetenciasPerfiles = new ArrayList<CompetenciasPerfiles>();
		
		for (int i = 0; i < banderaCompetencia.length; i++) {
			Competencias competencia = null;
			if(banderaCompetencia[i].equals("1")) {
				competencia = competenciaService.findByDescCompetencia(nombreCompetencia[i].trim());
			} else if (banderaCompetencia[i].equals("2")) {
				competencia = new Competencias();
				competencia.setDescCompetencias(nombreCompetencia[i].trim());
				competencia.setDescDefinicion(definicionCompetencia[i].trim());
				competenciaService.guardar(competencia);
			}
			 
			
			CompetenciasPerfiles cp = new CompetenciasPerfiles();
			cp.setPerfil(perfil);
			cp.setCompetencia(competencia);
			cp.setDescDefinicion(reactivoCompetencia[i].trim());
			
			listaCompetenciasPerfiles.add(cp);
			
		}
		
		competenciaPerfilService.guardarAll(listaCompetenciasPerfiles);
		
		
		return "redirect:/perfiles";
	}
	
	@RequestMapping(value = "/deletePerfilRecurso")
	@ResponseBody
	public String borrarPerfilRecurso(@RequestParam("c") Long codPerfil, Map<String, Object> model) {
		metaPerfilService.deleteByCodPerfil(codPerfil);
		competenciaPerfilService.deleteByCodPerfil(codPerfil);
		perfilRecursoService.borrar(codPerfil);
		return "1";
	} 
	
	@RequestMapping(value = "/verAsignados")
	public String verAsignados(@RequestParam("c") Long codPerfil, Map<String, Object> model) {
		List<Recurso> listaRecurso = new ArrayList<Recurso>();
		listaRecurso = recursoService.findRecursosByPerfil(codPerfil);
		model.put("listaRecursosAsignados", listaRecurso);
		return "layout/plantilla-perfiles :: modalAsignados";
	} 
	
	@RequestMapping(value = "/actualizarDefinicionMeta")
	@ResponseBody
	public String actualizarDefinicionMeta(@RequestParam("c") Long codMeta, @RequestParam("d") String definicionMeta, Map<String, Object> model) {
		Metas meta = metaService.findById(codMeta);
		meta.setDescDefinicion(definicionMeta);
		metaService.guardar(meta);
		return "1";
	} 
	
	@RequestMapping(value = "/actualizarDefinicionCompetencia")
	@ResponseBody
	public String actualizarDefinicionCompetencia(@RequestParam("c") Long codCompetencia, @RequestParam("d") String definicionCompetencia, Map<String, Object> model) {
		Competencias competencia = competenciaService.findById(codCompetencia);
		competencia.setDescDefinicion(definicionCompetencia);
		competenciaService.guardar(competencia);
		return "1";
	} 
	
	@RequestMapping(value = "/actualizaOrdenCard")
	@ResponseBody
	public void actualizaOrdenCard(@RequestParam(name="listaCards[]",required = false) Long[] listaCard) {
		List<PerfilRecurso> listaPerfiles = new ArrayList<>();
		for (int i = 0; i < listaCard.length; i++) {
			PerfilRecurso perfil = perfilRecursoService.findByCodPerfil(listaCard[i]);
			perfil.setValOrden(i);
			listaPerfiles.add(perfil);
		}
		perfilRecursoService.guardarAll(listaPerfiles);
	}
	
	

}
