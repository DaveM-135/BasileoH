package com.sophi.app.models.entity;

import java.util.ArrayList;
import java.util.List;

public class ProyectoRecursoDto {
	
	private List<ProyectoRecurso> listaRecursosProyecto;
	
	public ProyectoRecursoDto() {
		listaRecursosProyecto = new ArrayList<ProyectoRecurso>();
	}

	public void addProyectoRecurso(ProyectoRecurso proyectoRecurso) {
		this.listaRecursosProyecto.add(proyectoRecurso);
	}

	public List<ProyectoRecurso> getListaRecursosProyecto() {
		return listaRecursosProyecto;
	}

	public void setListaRecursosProyecto(List<ProyectoRecurso> listaRecursosProyecto) {
		this.listaRecursosProyecto = listaRecursosProyecto;
	}
	
	

}
